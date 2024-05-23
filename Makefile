configure:
	cd sqlcipher/ && \
		./configure && make sqlite3.c 
	cp sqlcipher/sqlite3.[ch] sqlcipher3/
	cd sqlcipher3 && \
		python setup.py build_static build

clone:
	# Download the latest version of SQLCipher source code and build the source
	# amalgamation files (sqlite3.c and sqlite3.h).
	# git clone https://github.com/sqlcipher/sqlcipher
	git clone --depth 1 https://github.com/sqlcipher/sqlcipher

install: clone, configure
