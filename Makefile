cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

all: ;

install:
	mkdir -p $(DESTDIR)/opt/vyatta/sbin
	install -m755 -t $(DESTDIR)/opt/vyatta/sbin \
		scripts/vyatta-ssh-key \
		scripts/vyatta-update-ssh.pl
	mkdir -p $(DESTDIR)/etc/ssh
	install -m644 -t $(DESTDIR)/etc/ssh sshd_not_to_be_run
	mkdir -p $(DESTDIR)/opt/vyatta/share/tmplscripts
	cd tmplscripts && $(cpiop) $(DESTDIR)/opt/vyatta/share/tmplscripts
	mkdir -p $(DESTDIR)/usr/share/configd/yang
	install -m644 -t $(DESTDIR)/usr/share/configd/yang \
		yang/vyatta-service-ssh-v1.yang
