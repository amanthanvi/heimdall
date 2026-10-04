//! Terminal-independent destination list state (contract §5): filtering,
//! selection, and key handling. The TUI renders this model; tests drive it
//! directly. Filtering is pure in-memory work (no I/O).

use crate::profile::Destination;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    Esc,
    Backspace,
    CtrlC,
    Char(char),
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    Select(String),
    Quit,
    Cancel,
}

#[derive(Debug, Clone)]
pub struct ListModel {
    items: Vec<Destination>,
    /// Pre-lowercased (alias, host) for filtering.
    keys: Vec<(String, String)>,
    filter: String,
    filtering: bool,
    /// Indices into `items` that match the filter, in profile order.
    shown: Vec<usize>,
    /// Position within `shown`.
    selected: usize,
}

impl ListModel {
    pub fn new(items: Vec<Destination>) -> Self {
        let keys = items
            .iter()
            .map(|d| (d.alias.to_lowercase(), d.host.to_lowercase()))
            .collect();
        let shown = (0..items.len()).collect();
        ListModel {
            items,
            keys,
            filter: String::new(),
            filtering: false,
            shown,
            selected: 0,
        }
    }

    pub fn total(&self) -> usize {
        self.items.len()
    }
    pub fn shown_len(&self) -> usize {
        self.shown.len()
    }
    pub fn filter(&self) -> &str {
        &self.filter
    }
    pub fn is_filtering(&self) -> bool {
        self.filtering
    }
    /// Selected position within the shown rows, if any rows are shown.
    pub fn selected(&self) -> Option<usize> {
        if self.shown.is_empty() {
            None
        } else {
            Some(self.selected)
        }
    }
    pub fn shown_items(&self) -> impl Iterator<Item = &Destination> {
        self.shown.iter().map(|&i| &self.items[i])
    }
    pub fn selected_item(&self) -> Option<&Destination> {
        self.selected().map(|s| &self.items[self.shown[s]])
    }

    /// Status line: `<shown>/<total>` plus the active filter text.
    pub fn status_line(&self) -> String {
        let mut s = format!("{}/{}", self.shown.len(), self.items.len());
        if self.filtering {
            s.push_str(&format!("  /{}", self.filter));
        } else if !self.filter.is_empty() {
            s.push_str(&format!("  filter: {}", self.filter));
        }
        s
    }

    /// Row text without the selection prefix. Narrow terminals (< 50 columns)
    /// show only the alias.
    pub fn row_text(d: &Destination, width: u16) -> String {
        if width < 50 {
            d.alias.clone()
        } else {
            format!("{}  {}@{}:{}", d.alias, d.account, d.host, d.port)
        }
    }

    fn refilter(&mut self) {
        let needle = self.filter.to_lowercase();
        self.shown = (0..self.items.len())
            .filter(|&i| {
                needle.is_empty()
                    || self.keys[i].0.contains(&needle)
                    || self.keys[i].1.contains(&needle)
            })
            .collect();
        // Contract §9 K9: every filter change resets the selection to the first shown row.
        self.selected = 0;
    }

    pub fn handle(&mut self, key: Key) -> Action {
        if key == Key::CtrlC {
            return Action::Cancel;
        }
        if self.filtering {
            match key {
                Key::Enter => self.filtering = false,
                Key::Esc => {
                    self.filtering = false;
                    self.filter.clear();
                    self.refilter();
                }
                Key::Backspace => {
                    self.filter.pop();
                    self.refilter();
                }
                Key::Char(c) if !c.is_control() => {
                    self.filter.push(c);
                    self.refilter();
                }
                Key::Up => self.up(),
                Key::Down => self.down(),
                _ => {}
            }
            return Action::None;
        }
        match key {
            Key::Up | Key::Char('k') => self.up(),
            Key::Down | Key::Char('j') => self.down(),
            Key::Char('/') => self.filtering = true,
            Key::Char('q') => return Action::Quit,
            Key::Enter => {
                if let Some(d) = self.selected_item() {
                    return Action::Select(d.alias.clone());
                }
            }
            _ => {}
        }
        Action::None
    }

    fn up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }
    fn down(&mut self) {
        if self.selected + 1 < self.shown.len() {
            self.selected += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::load_file;
    use std::path::PathBuf;

    fn model(name: &str) -> ListModel {
        // `$HEIMDALL_G02_FIXTURES` for relocated test runs, else the repository layout.
        let p = std::env::var_os("HEIMDALL_G02_FIXTURES")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/g02/profiles")
            })
            .join(name);
        ListModel::new(load_file(&p).unwrap().destinations)
    }

    fn typ(m: &mut ListModel, s: &str) {
        for c in s.chars() {
            m.handle(Key::Char(c));
        }
    }

    #[test]
    fn navigate_and_select() {
        let mut m = model("homelab.toml");
        assert_eq!(m.status_line(), "3/3");
        assert_eq!(m.handle(Key::Up), Action::None);
        m.handle(Key::Char('j'));
        m.handle(Key::Down);
        m.handle(Key::Down);
        assert_eq!(m.handle(Key::Enter), Action::Select("vps-東京".into()));
        m.handle(Key::Char('k'));
        assert_eq!(m.handle(Key::Enter), Action::Select("nas".into()));
        assert_eq!(m.handle(Key::Char('q')), Action::Quit);
        assert_eq!(m.handle(Key::CtrlC), Action::Cancel);
    }

    #[test]
    fn filter_mode() {
        let mut m = model("homelab.toml");
        m.handle(Key::Char('/'));
        assert!(m.is_filtering());
        typ(&mut m, "NAS");
        assert_eq!(m.shown_len(), 1, "case-insensitive over alias/host");
        assert_eq!(m.status_line(), "1/3  /NAS");
        m.handle(Key::Backspace);
        m.handle(Key::Backspace);
        m.handle(Key::Backspace);
        assert_eq!(m.shown_len(), 3);
        typ(&mut m, "東京");
        assert_eq!(m.shown_len(), 1, "non-ASCII filter");
        // q/j/k are text in filter mode
        m.handle(Key::Esc);
        assert_eq!(m.filter(), "");
        assert_eq!(m.shown_len(), 3);
        m.handle(Key::Char('/'));
        typ(&mut m, "vps1.example");
        assert_eq!(m.shown_len(), 1, "matches host");
        assert_eq!(
            m.handle(Key::Enter),
            Action::None,
            "Enter leaves filter mode"
        );
        assert!(!m.is_filtering());
        assert_eq!(m.status_line(), "1/3  filter: vps1.example");
        assert_eq!(m.handle(Key::Enter), Action::Select("vps-東京".into()));
        assert_eq!(m.handle(Key::CtrlC), Action::Cancel);
    }

    /// K9: append, Backspace and the Esc clear each reset the selection to the first
    /// shown row; leaving filter mode with Enter keeps it.
    #[test]
    fn k9_filter_edit_resets_selection_enter_keeps_it() {
        let mut m = model("homelab.toml");
        m.handle(Key::Down);
        m.handle(Key::Down);
        assert_eq!(m.selected(), Some(2));
        m.handle(Key::Char('/'));
        typ(&mut m, "e"); // all three rows still match ("e" in every alias/host)
        assert_eq!(m.shown_len(), 3);
        assert_eq!(m.selected(), Some(0), "append resets");
        m.handle(Key::Down);
        assert_eq!(m.selected(), Some(1));
        m.handle(Key::Backspace);
        assert_eq!(m.selected(), Some(0), "Backspace resets");
        m.handle(Key::Down);
        m.handle(Key::Down);
        m.handle(Key::Esc);
        assert_eq!(m.selected(), Some(0), "Esc clear resets");
        m.handle(Key::Char('/'));
        typ(&mut m, "e");
        m.handle(Key::Down);
        m.handle(Key::Down);
        assert_eq!(
            m.handle(Key::Enter),
            Action::None,
            "Enter leaves filter mode"
        );
        assert!(!m.is_filtering());
        assert_eq!(m.selected(), Some(2), "Enter keeps selection");
        assert_eq!(m.handle(Key::Enter), Action::Select("vps-東京".into()));
    }

    #[test]
    fn q_in_filter_mode_is_text_and_empty_enter_noop() {
        let mut m = model("homelab.toml");
        m.handle(Key::Char('/'));
        assert_eq!(m.handle(Key::Char('q')), Action::None);
        assert_eq!(m.filter(), "q");
        assert_eq!(m.shown_len(), 0);
        m.handle(Key::Enter);
        assert_eq!(m.handle(Key::Enter), Action::None, "nothing to select");
        assert_eq!(m.selected(), None);
    }

    #[test]
    fn large_filter_immediate() {
        let mut m = model("large-100.toml");
        assert_eq!(m.status_line(), "100/100");
        m.handle(Key::Char('/'));
        let t = std::time::Instant::now();
        typ(&mut m, "-db");
        assert_eq!(m.shown_len(), 25);
        assert!(t.elapsed() < std::time::Duration::from_millis(50));
    }

    #[test]
    fn narrow_rows() {
        let m = model("homelab.toml");
        let d = m.shown_items().next().unwrap();
        assert_eq!(ListModel::row_text(d, 49), "lab-server");
        assert_eq!(
            ListModel::row_text(d, 50),
            "lab-server  aman@lab.example.internal:22"
        );
    }
}
