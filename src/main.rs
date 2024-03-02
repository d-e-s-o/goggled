#![allow(clippy::let_unit_value)]

use std::cmp::min;
use std::collections::HashMap;
use std::env::var_os;
use std::pin::pin;
use std::ptr::null;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::ensure;
use anyhow::Context as _;
use anyhow::Error;
use anyhow::Result;

use clap::ArgAction;
use clap::Parser;

use tokio::time::sleep;

use tracing::debug;
use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing::trace;
use tracing::warn;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::FmtSubscriber;

use x11_dl::xlib::Xlib;
use x11_dl::xss::Xss as XScreenSaver;

use zbus::export::futures_util::future::select;
use zbus::export::futures_util::future::Either;
use zbus::export::futures_util::FutureExt as _;
use zbus::export::futures_util::StreamExt as _;
use zbus::fdo::DBusProxy;
use zbus::names::WellKnownName;
use zbus::zvariant::Value;
use zbus::Connection;
use zbus::MatchRule;
use zbus::MessageStream;
use zbus::MessageType;

/// Our "pool" of message IDs. 0 is treated specially by the
/// Notification service and, hence, intentionally not used.
static ID: AtomicU32 = AtomicU32::new(1);


/// Parse a duration from a string.
fn parse_duration(s: &str) -> Result<Duration> {
  let durations = [("s", 1), ("m", 60), ("h", 3600)];

  for (suffix, multiplier) in &durations {
    if let Some(base) = s.strip_suffix(suffix) {
      if let Ok(count) = base.parse::<u64>() {
        return Ok(Duration::from_secs(count * multiplier))
      }
    }
  }

  Err(anyhow!("invalid duration provided: {}", s))
}


/// A program/daemon sending notifications when the user should take a
/// break from staring at the screen.
#[derive(Debug, Parser)]
pub struct Args {
  /// The duration that, if the user has been "goggling" for this long,
  /// we post a notification.
  #[clap(long, default_value = "25m")]
  #[arg(value_parser = parse_duration)]
  pub goggle_duration: Duration,
  /// The duration that, if the system has been idle for this long, we
  /// reset the "goggling" duration.
  #[clap(long, default_value = "4m")]
  #[arg(value_parser = parse_duration)]
  pub idle_reset_duration: Duration,
  /// Increase verbosity (can be supplied multiple times).
  #[clap(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
  pub verbosity: u8,
}


// https://specifications.freedesktop.org/notification-spec/notification-spec-latest.html
async fn send_notification() -> Result<()> {
  let appname = env!("CARGO_BIN_NAME");
  let replaces_id = ID.fetch_add(1, Ordering::Relaxed);
  let icon = "";
  let summary = "o_O";
  let body = "";
  let mut hints = HashMap::new();
  let _ = hints.insert("resident", Value::Bool(true));
  // Never.
  let timeout = 0i32;

  let connection = Connection::session()
    .await
    .context("failed to establish D-Bus session connection")?;
  let bus = WellKnownName::from_static_str_unchecked("org.freedesktop.Notifications");
  let destination = Some(bus);
  let path = "/org/freedesktop/Notifications";
  let interface = "org.freedesktop.Notifications";
  let method = "Notify";

  let notify = || async {
    let msg_id = connection
      .call_method(
        destination.clone(),
        path,
        Some(interface),
        method,
        &(
          appname,
          replaces_id,
          icon,
          summary,
          body,
          [""; 0].as_slice(),
          &hints,
          timeout,
        ),
      )
      .await
      .with_context(|| format!("failed to call {method} method on {interface}"))?
      .body::<u32>()
      .context("failed to deserialize D-Bus message body")?;

    debug!(id = msg_id, "sent notification");
    Result::<_, Error>::Ok(msg_id)
  };

  let mut msg_id = notify().await?;

  // We loop here and wait for notification closure or, after 5 minutes,
  // resend the message, replacing the original. This is done so that if
  // the Notification service were to crash, we'd get back on track one
  // way or another (either by repopulating the message and awaiting its
  // closure anew or by erring out somehow).
  loop {
    let ping = sleep(Duration::from_secs(5 * 60)).then(|()| notify());
    let ping = pin!(ping);
    let wait = wait_for_action_signal(&connection, interface, msg_id);
    let wait = pin!(wait);

    match select(ping, wait).await {
      Either::Left((result, _)) => {
        msg_id = result?;
      },
      Either::Right((result, _)) => {
        let () = result?;
        debug!(id = msg_id, "notification closed");
        break Ok(())
      },
    }
  }
}


async fn wait_for_action_signal(connection: &Connection, interface: &str, id: u32) -> Result<()> {
  let action_signal_rule = MatchRule::builder()
    .msg_type(MessageType::Signal)
    .interface(interface)
    .context("failed to build action signal match rule")?
    .member("ActionInvoked")?
    .build();

  let proxy = DBusProxy::new(connection).await?;
  let () = proxy.add_match_rule(action_signal_rule).await?;

  let close_signal_rule = MatchRule::builder()
    .msg_type(MessageType::Signal)
    .interface(interface)
    .context("failed to build close signal match rule")?
    .member("NotificationClosed")?
    .build();
  let () = proxy.add_match_rule(close_signal_rule).await?;

  while let Some(result) = MessageStream::from(connection).next().await {
    let message = result.context("failed to retrieve D-Bus message")?;
    let header = message
      .header()
      .context("failed to retrieve D-Bus message header")?;
    if let MessageType::Signal = header
      .message_type()
      .context("failed to inquire D-Bus message type")?
    {
      match header
        .member()
        .context("failed to get D-Bus message header member")?
      {
        Some(name) if name == "ActionInvoked" => {
          let (nid, action) = message
            .body::<(u32, String)>()
            .context("failed to deserialize D-Bus message body")?;
          if nid == id {
            trace!(id, "notification action `{action}` invoked");
            break
          }
        },
        Some(name) if name == "NotificationClosed" => {
          let (nid, _reason) = message
            .body::<(u32, u32)>()
            .context("failed to deserialize D-Bus message body")?;
          if nid == id {
            trace!(id, "notification message closed");
            break
          }
        },
        Some(..) | None => (),
      }
    }
  }

  Ok(())
}


fn query_idle_time() -> Result<Duration> {
  let xlib = Xlib::open().context("failed to open xlib API")?;

  let display = unsafe { (xlib.XOpenDisplay)(null()) };
  ensure!(!display.is_null(), "failed to open X display");

  let xss = XScreenSaver::open().context("failed to open xscreensaver API")?;
  let info = unsafe { (xss.XScreenSaverAllocInfo)() };
  ensure!(
    !info.is_null(),
    "XScreenSaverAllocInfo failed to allocate memory"
  );
  let root = unsafe { (xlib.XDefaultRootWindow)(display) };
  let result = unsafe { (xss.XScreenSaverQueryInfo)(display, root, info) };
  ensure!(result != 0, "failed to query screen saver information");

  let idle_ms = unsafe { (*info).idle };
  let _result = unsafe { (xlib.XFree)(info.cast()) };

  let idle = Duration::from_millis(idle_ms);
  trace!("idle time is {idle:?}");
  Ok(idle)
}


async fn check_once(args: &Args, mut goggling_since: Instant) -> Result<Instant> {
  let idle = query_idle_time()?;
  if idle > args.idle_reset_duration {
    goggling_since = Instant::now();
    debug!("reset goggle time");
  } else if Instant::now() > goggling_since + args.goggle_duration {
    let () = send_notification().await?;
    goggling_since = Instant::now();
  }

  Ok(goggling_since)
}


#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
  let args = Args::parse();
  let level = match args.verbosity {
    0 => LevelFilter::WARN,
    1 => LevelFilter::INFO,
    2 => LevelFilter::DEBUG,
    _ => LevelFilter::TRACE,
  };

  let builder =
    FmtSubscriber::builder().with_timer(ChronoLocal::new("%Y-%m-%dT%H:%M:%S%.3f%:z".to_string()));

  if let Some(directive) = var_os(EnvFilter::DEFAULT_ENV) {
    let directive = directive
      .to_str()
      .with_context(|| format!("env var `{}` is not valid UTF-8", EnvFilter::DEFAULT_ENV))?;

    let subscriber = builder.with_env_filter(EnvFilter::new(directive)).finish();
    let () =
      set_global_subscriber(subscriber).with_context(|| "failed to set tracing subscriber")?;
  } else {
    let subscriber = builder.with_max_level(level).finish();
    let () =
      set_global_subscriber(subscriber).with_context(|| "failed to set tracing subscriber")?;
  };

  debug!(
    "using goggle duration of {:?} and idle reset {:?}",
    args.goggle_duration, args.idle_reset_duration
  );

  let mut goggling_since = Instant::now();
  debug!("started goggle time tracking");
  let sleep_duration = min(args.goggle_duration, args.idle_reset_duration) / 3;

  loop {
    let () = sleep(sleep_duration).await;

    match check_once(&args, goggling_since).await {
      Ok(goggling) => goggling_since = goggling,
      Err(err) => warn!("{err:#}"),
    }
  }
}


#[cfg(test)]
mod tests {
  use super::*;


  /// Make sure that we can parse durations properly.
  #[test]
  fn duration_parsing() {
    assert_eq!(parse_duration("1s").unwrap(), Duration::from_secs(1));
    assert_eq!(parse_duration("35s").unwrap(), Duration::from_secs(35));
    assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
    assert_eq!(
      parse_duration("5h").unwrap(),
      Duration::from_secs(5 * 60 * 60)
    );
    assert!(parse_duration("xxx")
      .unwrap_err()
      .to_string()
      .contains("invalid duration provided"));
  }
}
