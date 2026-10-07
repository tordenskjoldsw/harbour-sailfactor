Name:       harbour-sailfactor

Summary:    Authenticator for TOTP codes in a KeePass-compatible file
Version:    0.1.0
Release:    1
License:    MIT
URL:        https://github.com/tordenskjoldsw/harbour-sailfactor
Source0:    %{name}-%{version}.tar.bz2
Requires:   sailfishsilica-qt5 >= 0.10.9
BuildRequires:  pkgconfig(sailfishapp) >= 1.0.2
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5Qml)
BuildRequires:  pkgconfig(Qt5Quick)
BuildRequires:  pkgconfig(Qt5Multimedia)
BuildRequires:  desktop-file-utils
BuildRequires:  rust
BuildRequires:  cargo

%description
SailFactor is an independent, open-source authenticator for TOTP codes.
It keeps the accounts in an encrypted KeePass-compatible (KDBX4) file,
apart from the password manager.

%prep
%setup -q -n %{name}-%{version}

%build

%qmake5 VERSION=%{version}

%make_build

%install
%qmake5_install

desktop-file-install --delete-original       \
  --dir %{buildroot}%{_datadir}/applications             \
   %{buildroot}%{_datadir}/applications/*.desktop

%files
%{_bindir}/%{name}
%{_datadir}/%{name}
%{_datadir}/applications/%{name}.desktop
%{_datadir}/icons/hicolor/*/apps/%{name}.png
