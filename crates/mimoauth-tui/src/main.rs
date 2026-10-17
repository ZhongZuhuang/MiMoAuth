//! Fullscreen TUI auth agent for terminal sessions (SSH / TTY).
//! Same protocol as the GUI: `mimoauth-tui --auth-id <id>`.
//! Exit codes: 0 = allow, 1 = deny, 2 = timeout, 3 = error.

use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use mimoauth_common::dbus::Auth1ProxyBlocking;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

fn parse_auth_id() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--auth-id" {
            return args.next();
        }
        if let Some(id) = a.strip_prefix("--auth-id=") {
            return Some(id.to_string());
        }
    }
    None
}

fn zh() -> bool {
    let lang = std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LC_MESSAGES"))
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default();
    lang.starts_with("zh")
}

struct Ui {
    description: String,
    command: String,
    source: String,
    deadline: Instant,
    password: String,
    message: String,
    message_is_error: bool,
    zh: bool,
}

fn source_title(zh: bool, source: &str) -> &'static str {
    match (zh, source) {
        (true, "mimo") => "MiMo 正在请求权限",
        (true, "ai") => "AI 正在请求权限",
        (true, _) => "正在请求系统权限",
        (false, "mimo") => "MiMo is requesting access",
        (false, "ai") => "AI is requesting access",
        (false, _) => "Requesting system access",
    }
}

fn source_brand(zh: bool, source: &str) -> &'static str {
    match (zh, source) {
        (true, "mimo") => "由 MiMo Desktop 发起",
        (true, "ai") => "由 AI Agent 发起",
        (true, _) => "来自你的终端操作",
        (false, "mimo") => "From MiMo Desktop",
        (false, "ai") => "From an AI agent",
        (false, _) => "From your terminal session",
    }
}

fn draw(f: &mut Frame, ui: &Ui) {
    let area = f.area();
    let w = area.width.min(72).max(30);
    let h = 14;
    let x = area.width.saturating_sub(w) / 2;
    let y = area.height.saturating_sub(h) / 2;
    let rect = Rect::new(x, y, w, h);
    f.render_widget(Clear, rect);

    let title = source_title(ui.zh, &ui.source);
    let brand = source_brand(ui.zh, &ui.source);
    let cmd_cap = if ui.zh { "命令" } else { "Command" };
    let prompt = if ui.zh {
        "输入密码后回车 · Esc 取消"
    } else {
        "Enter to authenticate · Esc cancels"
    };
    let secs = ui.deadline.saturating_duration_since(Instant::now()).as_secs();
    let remain = if ui.zh {
        format!("剩余 {secs} 秒")
    } else {
        format!("{secs}s remaining")
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(title);
    let inner = block.inner(rect);
    f.render_widget(block, rect);

    let mut lines = vec![
        Line::from(Span::styled(
            brand,
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(ui.description.clone()),
    ];
    if !ui.command.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("{cmd_cap}:"),
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(
            ui.command.clone(),
            Style::default().fg(Color::Yellow),
        )));
    }
    lines.push(Line::from(""));
    let masked = "*".repeat(ui.password.len());
    lines.push(Line::from(vec![
        Span::raw(if ui.zh { "密码: " } else { "Password: " }),
        Span::styled(masked, Style::default().fg(Color::Green)),
        Span::styled("▌", Style::default().fg(Color::Cyan)),
    ]));
    if !ui.message.is_empty() {
        let color = if ui.message_is_error {
            Color::Red
        } else {
            Color::DarkGray
        };
        lines.push(Line::from(Span::styled(ui.message.clone(), Style::default().fg(color))));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        prompt,
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(Span::styled(
        remain,
        Style::default().fg(Color::DarkGray),
    )));
    f.render_widget(Paragraph::new(lines), inner);
}

fn run(
    proxy: &Auth1ProxyBlocking,
    auth_id: &str,
    description: String,
    command: String,
    source: String,
    deadline: Instant,
) -> Result<u8, String> {
    let mut terminal: Terminal<CrosstermBackend<Stdout>> = {
        enable_raw_mode().map_err(|e| format!("raw mode: {e}"))?;
        let mut out = io::stdout();
        execute!(out, EnterAlternateScreen).map_err(|e| format!("alt screen: {e}"))?;
        Terminal::new(CrosstermBackend::new(out)).map_err(|e| format!("terminal: {e}"))?
    };
    let zh = zh();
    let mut ui = Ui {
        description,
        command,
        source,
        deadline,
        password: String::new(),
        message: String::new(),
        message_is_error: true,
        zh,
    };

    let result = loop {
        if Instant::now() >= ui.deadline {
            let _ = proxy.cancel_auth(auth_id);
            break 2u8;
        }
        terminal
            .draw(|f| draw(f, &ui))
            .map_err(|e| format!("draw: {e}"))?;
        if !event::poll(Duration::from_millis(120)).map_err(|e| format!("poll: {e}"))? {
            continue;
        }
        match event::read().map_err(|e| format!("event: {e}"))? {
            Event::Key(k) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Esc => {
                    let _ = proxy.cancel_auth(auth_id);
                    break 1u8;
                }
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    let _ = proxy.cancel_auth(auth_id);
                    break 1u8;
                }
                KeyCode::Enter => {
                    if ui.password.is_empty() {
                        continue;
                    }
                    match proxy.submit_password(auth_id, &ui.password) {
                        Ok((true, _)) => break 0u8,
                        Ok((false, reason)) => {
                            if reason == "expired" || reason == "not-found" {
                                break 2u8;
                            }
                            ui.password.clear();
                            ui.message = if zh {
                                "密码验证失败，请重试".into()
                            } else {
                                "Password verification failed, try again".into()
                            };
                            ui.message_is_error = true;
                        }
                        Err(e) => {
                            ui.message = format!("D-Bus: {e}");
                            ui.message_is_error = true;
                        }
                    }
                }
                KeyCode::Backspace => {
                    ui.password.pop();
                }
                KeyCode::Char(c) => {
                    if ui.password.len() < 256 {
                        ui.password.push(c);
                    }
                }
                _ => {}
            },
            _ => {}
        }
    };

    // leave the alternate screen cleanly
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
    Ok(result)
}

fn main() {
    let code = (|| -> Result<u8, String> {
        let auth_id = parse_auth_id().ok_or("usage: mimoauth-tui --auth-id <id>")?;
        let conn = zbus::blocking::Connection::session()
            .map_err(|e| format!("session bus: {e}"))?;
        let proxy = Auth1ProxyBlocking::new(&conn)
            .map_err(|e| format!("cannot reach mimoauthd: {e}"))?;
        let (description, command, source, remaining_ms) = proxy
            .get_pending_request(&auth_id)
            .map_err(|e| format!("no pending request: {e}"))?;
        let deadline = Instant::now() + Duration::from_millis(remaining_ms.max(1000));
        run(&proxy, &auth_id, description, command, source, deadline)
    })();
    match code {
        Ok(c) => std::process::exit(c as i32),
        Err(e) => {
            eprintln!("mimoauth-tui: {e}");
            std::process::exit(3);
        }
    }
}
