clean:
	rm -rf linux
	rm *.deb

linux:
	make -C linux clean
	make -C linux olddefconfig
	make -C linux -j 3 deb-pkg
