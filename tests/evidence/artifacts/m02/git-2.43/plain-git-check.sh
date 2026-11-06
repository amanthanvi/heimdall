#!/bin/sh
# Plain git reproduction in a scratch HOME (arg1 = scratch dir). Output is redacted
# inside this script: the scratch path becomes <scratch>.
S=$1
mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
for U in 022 002; do
  umask $U
  H="$S/home-$U"; mkdir -p "$H"
  env -i PATH=/usr/bin:/bin HOME="$H" XDG_CONFIG_HOME="$H/.config" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null sh -c '
    mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
    echo "umask=$(umask)"
    git --version
    mkdir -p "$HOME/.config/git"
    printf "[user]\n\tname = Xdg\n" > "$HOME/.config/git/config"
    printf "[user]\n\temail = scratch@example.invalid\n" > "$HOME/.gitconfig"
    echo "xdg_dir_mode=$(mode "$HOME/.config/git")  xdg_file_mode=$(mode "$HOME/.config/git/config")  home_file_mode=$(mode "$HOME/.gitconfig")"
    echo "--- git var GIT_CONFIG_GLOBAL (read order)"; git var GIT_CONFIG_GLOBAL; echo "exit=$?"
    cd /
    echo "--- parse check used before B_git is exchanged: git config --file <staged> --no-includes --list"
    printf "[include]\n\tpath = /nonexistent-hm-test\n[core]\n\tsshCommand = x\n" > "$HOME/.config/git/staged"
    git config --file "$HOME/.config/git/staged" --no-includes --list >/dev/null; echo "exit=$?"
    echo "--- include in the first-read (XDG) file: effective value"
    printf "[include]\n\tpath = %s/inc\n" "$HOME" > "$HOME/.config/git/config"
    printf "[core]\n\tsshCommand = incl\n" > "$HOME/inc"
    git config --includes --show-origin --get core.sshCommand; echo "exit=$?"
    echo "--- a value in ~/.gitconfig, read after the XDG file, wins"
    printf "[core]\n\tsshCommand = ssh -6\n" >> "$HOME/.gitconfig"
    git config --includes --show-origin --get core.sshCommand; echo "exit=$?"
    echo "--- git config --global (reads and writes ~/.gitconfig only when it exists)"
    git config --global --includes --show-origin --get-all core.sshCommand; echo "exit=$?"
  ' 2>&1
done | sed "s#$S#<scratch>#g; s#/private<scratch>#<scratch>#g"
