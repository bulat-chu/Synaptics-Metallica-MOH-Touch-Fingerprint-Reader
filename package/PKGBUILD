# Maintainer: (you)
# python-validity with Synaptics 06cb:00a2 (Metallica MOH) support from PR #261
# (enroll on host, match on chip). Works together with open-fprintd.
pkgname=python-validity-moh
pkgver=0.15.pr261_840cfbe
pkgrel=1
pkgdesc='Validity/Synaptics fingerprint driver for open-fprintd, with 06cb:00a2 (MoH) support from PR #261'
arch=('any')
url='https://github.com/uunicorn/python-validity/pull/261'
license=('MIT')
depends=('python' 'python-cryptography' 'python-pyusb' 'python-yaml' 'python-numpy'
         'python-dbus' 'python-gobject' 'innoextract' 'open-fprintd')
optdepends=('fprintd-clients: fprintd-enroll/verify/list tools and the pam_fprintd module')
provides=("python-validity=0.15")
conflicts=('python-validity')
backup=('etc/python-validity/dbus-service.yaml')
install=python-validity-moh.install
# pinned to the commit that was tested on 06cb:00a2 (branch moh-review-fixes of dmitriy-myz's fork)
source=("python-validity::git+https://github.com/dmitriy-myz/python-validity.git#commit=840cfbe")
sha256sums=('SKIP')

package() {
  cd "$srcdir/python-validity"

  local site
  site=$(python -c 'import site; print(site.getsitepackages()[0])')

  # python package
  install -d "$pkgdir$site"
  cp -r validitysensor "$pkgdir$site/"
  find "$pkgdir$site/validitysensor" -name '__pycache__' -prune -exec rm -rf {} +
  python -m compileall -q -d "$site/validitysensor" "$pkgdir$site/validitysensor"

  # tools
  install -Dm755 bin/validity-sensors-firmware "$pkgdir/usr/bin/validity-sensors-firmware"
  install -Dm755 bin/validity-led-dance        "$pkgdir/usr/bin/validity-led-dance"

  # daemon, D-Bus policy (open-fprintd must be allowed to call it), systemd unit
  install -Dm755 dbus_service/dbus-service \
      "$pkgdir/usr/lib/python-validity/dbus-service"
  install -Dm644 dbus_service/io.github.uunicorn.Fprint.conf \
      "$pkgdir/usr/share/dbus-1/system.d/io.github.uunicorn.Fprint.conf"
  install -Dm644 debian/python3-validity.service \
      "$pkgdir/usr/lib/systemd/system/python3-validity.service"

  # udev: upstream rule lists 138a:0090, 138a:0097 and 06cb:009a only; add 06cb:00a2
  sed '/idProduct}=="009a"/a ATTRS{idVendor}=="06cb", ATTRS{idProduct}=="00a2", GOTO="python_validity_match"' \
      debian/python3-validity.udev > 40-python3-validity.rules
  install -Dm644 40-python3-validity.rules \
      "$pkgdir/usr/lib/udev/rules.d/40-python3-validity.rules"

  # user -> SID mapping (by default generated from the uid)
  install -Dm600 etc/python-validity/dbus-service.yaml \
      "$pkgdir/etc/python-validity/dbus-service.yaml"

  # helper scripts (factory reset, MoH enrollment/list/match from the command line)
  for s in dbus-cmd.py lsdbus.py factory-reset.py prototype.py enroll_moh_chip.py; do
    install -Dm755 "scripts/$s" "$pkgdir/usr/share/python-validity/playground/$s"
  done

  install -Dm644 README.md   "$pkgdir/usr/share/doc/$pkgname/README.md"
  install -Dm644 LICENSE     "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
