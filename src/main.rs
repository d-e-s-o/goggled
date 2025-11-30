// Copyright (C) 2024-2025 Daniel Mueller <deso@posteo.net>
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::let_unit_value)]

use std::cmp::min;
use std::collections::HashMap;
use std::env::var_os;
use std::ffi::CStr;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::pin::pin;
use std::ptr::null;
use std::ptr::null_mut;
use std::ptr::NonNull;
use std::slice;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::ensure;
use anyhow::Context as _;
use anyhow::Error;
use anyhow::Result;

use clap::ArgAction;
use clap::Parser;

use futures_util::future::select;
use futures_util::future::Either;
use futures_util::FutureExt as _;
use futures_util::StreamExt as _;

use tokio::time::sleep;

use tracing::debug;
use tracing::error;
use tracing::field::debug;
use tracing::field::DebugValue;
use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing::trace;
use tracing::warn;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::FmtSubscriber;

use x11_dl::xlib::Atom;
use x11_dl::xlib::Display;
use x11_dl::xlib::Success;
use x11_dl::xlib::Window;
use x11_dl::xlib::XErrorEvent;
use x11_dl::xlib::Xlib;
use x11_dl::xlib::XA_ATOM;
use x11_dl::xlib::XA_WINDOW;
use x11_dl::xss::Xss as XScreenSaver;

use zbus::connection::Builder as ConnectionBuilder;
use zbus::connection::Connection;
use zbus::fdo::DBusProxy;
use zbus::message::Type as MessageType;
use zbus::names::WellKnownName;
use zbus::zvariant::Value;
use zbus::Address;
use zbus::MatchRule;
use zbus::MessageStream;

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

  Err(anyhow!("invalid duration provided: {s}"))
}


/// A program/daemon sending notifications when the user should take a
/// break from staring at the screen.
#[derive(Debug, Parser)]
#[clap(version = env!("VERSION"))]
pub struct Args {
  /// The duration that, if the user has been "goggling" for this long,
  /// we post a notification.
  #[clap(long, default_value = "25m", value_parser = parse_duration)]
  pub goggle_duration: Duration,
  /// The duration that, if the system has been idle for this long, we
  /// reset the "goggling" duration.
  #[clap(long, default_value = "4m", value_parser = parse_duration)]
  pub idle_reset_duration: Duration,
  /// Increase verbosity (can be supplied multiple times).
  #[clap(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
  pub verbosity: u8,
}


struct OpenDisplay<'xlib> {
  /// The `Xlib` instance we work with.
  xlib: &'xlib Xlib,
  /// The opened display.
  display: NonNull<Display>,
}

impl<'xlib> OpenDisplay<'xlib> {
  fn new(xlib: &'xlib Xlib) -> Result<Self> {
    let display = unsafe { (xlib.XOpenDisplay)(null()) };
    let display = NonNull::new(display).context("failed to open X display")?;

    let slf = Self { xlib, display };
    Ok(slf)
  }

  fn as_ptr(&self) -> *mut Display {
    self.display.as_ptr()
  }
}

impl Drop for OpenDisplay<'_> {
  fn drop(&mut self) {
    let _result = unsafe { (self.xlib.XCloseDisplay)(self.display.as_ptr()) };
  }
}


struct XGuard<'xlib, T> {
  /// The `Xlib` instance we work with.
  xlib: &'xlib Xlib,
  /// The data being guarded.
  data: *mut T,
}

impl<'xlib, T> XGuard<'xlib, T> {
  fn new(xlib: &'xlib Xlib, data: *mut T) -> Self {
    Self { xlib, data }
  }
}

impl<T> Drop for XGuard<'_, T> {
  fn drop(&mut self) {
    let _result = unsafe { (self.xlib.XFree)(self.data.cast()) };
  }
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

  let address = Address::session().context("failed to get D-Bus session address")?;
  let connection = ConnectionBuilder::address(address.clone())
    .with_context(|| format!("failed to create connection builder for address {address}"))?
    .build()
    .await
    .with_context(|| format!("failed to establish D-Bus session connection to {address}"))?;

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
      .body()
      .deserialize::<u32>()
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
    let header = message.header();
    if let MessageType::Signal = header.message_type() {
      match header.member() {
        Some(name) if name == "ActionInvoked" => {
          let (nid, _action) = message
            .body()
            .deserialize::<(u32, String)>()
            .context("failed to deserialize D-Bus message body")?;
          if nid == id {
            break
          }
        },
        Some(name) if name == "NotificationClosed" => {
          let (nid, _reason) = message
            .body()
            .deserialize::<(u32, u32)>()
            .context("failed to deserialize D-Bus message body")?;
          if nid == id {
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
  let display = OpenDisplay::new(&xlib)?;

  let xss = XScreenSaver::open().context("failed to open xscreensaver API")?;
  let info = unsafe { (xss.XScreenSaverAllocInfo)() };
  ensure!(
    !info.is_null(),
    "XScreenSaverAllocInfo failed to allocate memory"
  );
  let _guard = XGuard::new(&xlib, info);

  let root = unsafe { (xlib.XDefaultRootWindow)(display.as_ptr()) };
  let result = unsafe { (xss.XScreenSaverQueryInfo)(display.as_ptr(), root, info) };
  ensure!(result != 0, "failed to query screen saver information");

  let idle_ms = unsafe { (*info).idle };
  let idle = Duration::from_millis(idle_ms);
  Ok(idle)
}


/// Retrieve the currently active window.
// For debugging matters, the result can be double checked from a shell
// using `xprop -root 32x '\t$0' _NET_ACTIVE_WINDOW`.
fn active_window() -> Result<Option<Window>> {
  let xlib = Xlib::open().context("failed to open xlib API")?;
  let display = OpenDisplay::new(&xlib)?;

  let only_if_exists = 0;
  let property = unsafe {
    (xlib.XInternAtom)(
      display.as_ptr(),
      b"_NET_ACTIVE_WINDOW\0".as_slice().as_ptr().cast(),
      only_if_exists,
    )
  };
  ensure!(
    property != 0,
    "failed to retrieve X11 NET_ACTIVE_WINDOW atom"
  );

  let root = unsafe { (xlib.XDefaultRootWindow)(display.as_ptr()) };

  let offset = 0;
  let length = 1;
  let delete = 0;
  let request_type = XA_WINDOW;
  let mut type_return = 0 as Atom;
  let mut format_return = 0;
  let mut items_return = 0;
  let mut bytes_left = 0;
  let mut data = null_mut();

  let result = unsafe {
    (xlib.XGetWindowProperty)(
      display.as_ptr(),
      root,
      property,
      offset,
      length,
      delete,
      request_type,
      &mut type_return,
      &mut format_return,
      &mut items_return,
      &mut bytes_left,
      &mut data,
    )
  };
  ensure!(
    result == Success.into(),
    "failed to retrieve X11 window property"
  );
  ensure!(!data.is_null(), "XGetWindowProperty return no data");
  let _guard = XGuard::new(&xlib, data);

  ensure!(
    type_return == XA_WINDOW,
    "XGetWindowProperty returned unexpected property: {type_return}"
  );
  ensure!(
    format_return == u32::BITS as _,
    "XGetWindowProperty returned unexpected format: {format_return}"
  );
  ensure!(
    items_return == 1,
    "XGetWindowProperty returned unexpected number of items: {items_return}"
  );
  ensure!(
    bytes_left == 0,
    "XGetWindowProperty performed partial read ({bytes_left} bytes left)"
  );

  let window = unsafe { *data.cast::<Window>() };
  // If no window is active the result is 0x0.
  let window = if window != 0x0 { Some(window) } else { None };
  Ok(window)
}


fn is_fullscreen(window: Window) -> Result<bool> {
  let xlib = Xlib::open().context("failed to open xlib API")?;
  let display = OpenDisplay::new(&xlib)?;

  let only_if_exists = 0;
  let fullscreen = unsafe {
    (xlib.XInternAtom)(
      display.as_ptr(),
      b"_NET_WM_STATE_FULLSCREEN\0".as_slice().as_ptr().cast(),
      only_if_exists,
    )
  };
  ensure!(
    fullscreen != 0,
    "failed to retrieve X11 NET_WM_STATE_FULLSCREEN atom"
  );

  let property = unsafe {
    (xlib.XInternAtom)(
      display.as_ptr(),
      b"_NET_WM_STATE\0".as_slice().as_ptr().cast(),
      only_if_exists,
    )
  };
  ensure!(property != 0, "failed to retrieve X11 NET_WM_STATE atom");

  // TODO: We should probably support invoking `XGetWindowProperty` in a
  //       loop to work with <1024 elements at a time while having no
  //       upper limit.
  let offset = 0;
  // Maximum number of properties/hints we may retrieve.
  let length = 1024;
  let delete = 0;
  let request_type = XA_ATOM;
  let mut type_return = 0 as Atom;
  let mut format_return = 0;
  let mut items_return = 0;
  let mut bytes_left = 0;
  let mut data = null_mut();

  let result = unsafe {
    (xlib.XGetWindowProperty)(
      display.as_ptr(),
      window,
      property,
      offset,
      length,
      delete,
      request_type,
      &mut type_return,
      &mut format_return,
      &mut items_return,
      &mut bytes_left,
      &mut data,
    )
  };
  ensure!(
    result == Success.into(),
    "failed to retrieve X11 window property"
  );

  if type_return == 0 {
    // If the _NET_WM_STATE atom doesn't exist at all,
    // `XGetWindowProperty` returns `Success` and sets the return type
    // to 0. For us, that is enough to conclude that the window is not
    // in fullscreen mode.
    return Ok(false)
  }

  ensure!(!data.is_null(), "XGetWindowProperty return no data");
  let _guard = XGuard::new(&xlib, data);

  ensure!(
    type_return == XA_ATOM,
    "XGetWindowProperty returned unexpected property: {type_return}"
  );
  ensure!(
    bytes_left == 0,
    "XGetWindowProperty performed partial read ({bytes_left} bytes left)"
  );

  let hints = unsafe { slice::from_raw_parts(data.cast::<Atom>(), items_return as _) };
  let fullscreen = hints.contains(&fullscreen);

  Ok(fullscreen)
}


fn init_xlib_error_handler() -> Result<()> {
  extern "C" fn error_handler(display: *mut Display, event: *mut XErrorEvent) -> i32 {
    let xlib = Xlib::open().context("failed to open xlib API").unwrap();
    // TODO: Should use `MaybeUninit` here.
    let mut buf = [0u8; 1024];
    let event = unsafe { &*event };
    let _result = unsafe {
      (xlib.XGetErrorText)(
        display,
        event.error_code.into(),
        buf.as_mut_slice().as_mut_ptr().cast(),
        buf.len() as _,
      )
    };

    let err = CStr::from_bytes_until_nul(&buf)
      .ok()
      .map(CStr::to_string_lossy);
    error!(
      r#"X Error of failed request:  {err}
    Major opcode of failed request:  {major}
    Resource id in failed request:  {resid:#x}
    Serial number of failed request:  {serial}"#,
      err = err.unwrap_or_default(),
      major = event.request_code,
      resid = event.resourceid,
      serial = event.serial
    );

    0
  }

  extern "C" fn io_error_handler(_display: *mut Display) -> i32 {
    error!("encountered X I/O error");
    0
  }

  let xlib = Xlib::open().context("failed to open xlib API")?;

  let _prev = unsafe { (xlib.XSetErrorHandler)(Some(error_handler)) };
  let _prev = unsafe { (xlib.XSetIOErrorHandler)(Some(io_error_handler)) };

  Ok(())
}


/// A type for displaying the value of a [`Window`].
struct DebugWindow {
  window: Option<Window>,
}

impl Debug for DebugWindow {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    match self.window {
      None => f.write_str("none"),
      Some(window) => f.write_fmt(format_args!("{:#x}", window)),
    }
  }
}


fn debug_window(window: Option<Window>) -> DebugValue<DebugWindow> {
  debug(DebugWindow { window })
}


struct Daemon {
  /// The duration that, if the user has been "goggling" for this long,
  /// we post a notification.
  goggle_duration: Duration,
  /// The duration that, if the system has been idle for this long, we
  /// reset the "goggling" duration.
  idle_reset_duration: Duration,
  /// The time for which the user was determined to have been goggling.
  goggling_for: Duration,
}

impl Daemon {
  fn new(goggle_duration: Duration, idle_reset_duration: Duration) -> Self {
    Self {
      goggle_duration,
      idle_reset_duration,
      goggling_for: Duration::from_secs(0),
    }
  }

  async fn run_once(&mut self) -> Result<()> {
    let sleep_duration = min(self.goggle_duration, self.idle_reset_duration) / 3;
    let () = sleep(sleep_duration).await;

    let idle = query_idle_time()?;
    trace!(idle_time = ?idle);

    if idle > self.idle_reset_duration {
      self.goggling_for = Duration::from_secs(0);
      trace!("reset goggle time");
    } else {
      let window = active_window()?;
      trace!(active_window = debug_window(window));

      let paused = if let Some(window) = window {
        let fullscreen = is_fullscreen(window)?;
        trace!(fullscreen);
        // When in fullscreen mode we pause advancing the goggle time
        // until the next check.
        fullscreen
      } else {
        // No active window means we pause advancing the goggle time
        // until the next check, assuming we actually were idle for a
        // little while (to weed out cases where the user may just have
        // momentarily have no window active).
        idle >= sleep_duration / 3
      };

      if !paused {
        self.goggling_for += sleep_duration;

        if self.goggling_for > self.goggle_duration {
          // We hit the goggle time. But we only send a notification if
          // the user has not been idle for one full interval, as there
          // is no point in notifying a user not present.
          if idle < sleep_duration {
            let () = send_notification().await?;
            self.goggling_for = Duration::from_secs(0);
          } else {
            trace!("user seems idle; not notifying right now");
          }
        }
      }
    }

    debug!(goggle_time = ?self.goggling_for);
    Ok(())
  }

  async fn run(&mut self) -> ! {
    loop {
      if let Err(err) = self.run_once().await {
        warn!("{err:#}")
      }
    }
  }
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

  let () = init_xlib_error_handler()?;

  debug!(
    "using goggle duration of {:?} and idle reset {:?}",
    args.goggle_duration, args.idle_reset_duration
  );

  let mut daemon = Daemon::new(args.goggle_duration, args.idle_reset_duration);
  daemon.run().await
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
