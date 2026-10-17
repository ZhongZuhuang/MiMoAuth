# RPM spec for MiMoAuth — build with:
#   spectool -g -R mimoauth.spec   # or place sources manually
#   rpmbuild -ba mimoauth.spec
Name:           mimoauth
Version:        0.1.0
Release:        1%{?dist}
Summary:        polkit-style authorization framework for AI desktops
License:        MIT
URL:            https://github.com/ZhongZuhuang/MiMoAuth
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo, rust
BuildRequires:  gtk4-devel, libadwaita-devel, pam-devel, pkgconfig
Requires:       gtk4, libadwaita, pam, dbus-libs
Recommends:     fprintd

%description
Session daemon with GTK4 authentication agent (password + fingerprint),
CLI toolchain (mimoauthctl) for AI agents, and optional sudo integration
via PAM (pam_exec). Independent of polkit — works without it.

%prep
%autosetup -n %{name}-%{version}

%build
cargo build --release --workspace

%install
install -Dm755 target/release/mimoauthd    %{buildroot}%{_bindir}/mimoauthd
install -Dm755 target/release/mimoauthctl  %{buildroot}%{_bindir}/mimoauthctl
install -Dm755 target/release/mimoauth-gui %{buildroot}%{_bindir}/mimoauth-gui
install -Dm644 data/systemd/mimoauthd.service %{buildroot}%{_userunitdir}/mimoauthd.service
install -Dm644 data/pam.d/mimoauth %{buildroot}%{_sysconfdir}/pam.d/mimoauth
install -Dm644 data/pam.d/sudo-mimoauth %{buildroot}%{_docdir}/%{name}/sudo-mimoauth.howto
install -Dm644 skills/mimoauth/SKILL.md %{buildroot}%{_datadir}/%{name}/skills/mimoauth/SKILL.md
install -Dm644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE

%files
%license LICENSE
%doc README.md
%{_bindir}/mimoauthd
%{_bindir}/mimoauthctl
%{_bindir}/mimoauth-gui
%{_userunitdir}/mimoauthd.service
%config(noreplace) %{_sysconfdir}/pam.d/mimoauth
%{_docdir}/%{name}/sudo-mimoauth.howto
%{_datadir}/%{name}/skills/mimoauth/SKILL.md

%changelog
* Fri Oct 17 2026 MiMo Assistant <mimo@users.noreply.github.com> - 0.1.0-1
- Initial RPM package
