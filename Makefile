.SILENT:
all:
	@echo
	@echo " Options:"
	@echo "  .  make clean"
	@echo "  .  make svnclean"
	@echo "  .  make tarball"
	@echo "  .  make patcher"
	@echo
	
clean:
	make -C server clean
	make -C client clean
	make -C honeycomb clean
	rm -rf hive.tar Logs

tarball:
	@tar --exclude .svn --exclude HiveServer.sdf --exclude *.gz --exclude *.tar --exclude *.tgz -cvf hive.tar * >/dev/null

ilm-tar:
	tar --exclude .svn --exclude HiveServer.sdf --exclude *.gz --exclude *.tar --exclude *.tgz -czvf hive-ilm-1.1.tgz client/ libs/ ilm-client/

patcher:
	cd server && make clean && make linux-x86
	cd server && make clean && make mikrotik-x86
	cd server && make clean && make mikrotik-ppc
	cd server && make clean && make mikrotik-mipsbe
	cd server && make clean && make mikrotik-mipsle
	cp server/hived-linux-i686 client/hived-linux-i386-unpatched
	cp server/hived-mikrotik-i386 client/hived-mikrotik-i386-unpatched
	cp server/hived-mikrotik-ppc client/hived-mikrotik-ppc-unpatched
	cp server/hived-mikrotik-mipsbe client/hived-mikrotik-mipsbe-unpatched
	cp server/hived-mikrotik-mipsle client/hived-mikrotik-mipsle-unpatched
	cd client && make clean && make patcher

linux-x86:
	@make -C server $@
	@echo $@

deliverables:	tarball
	rm -rf deliverables/*
	mkdir -p deliverables/BIN
	mkdir -p deliverables/DOC
	mkdir -p deliverables/SRC
	mkdir -p deliverables/OTHER
	bzip2 -fc hive.tar > deliverables/SRC/hive.tar.bz2
	cp -a ilm-client/CCS.xml* deliverables/BIN
	cp -a ilm-client/cutthroat* deliverables/BIN
	cp -a ilm-client/hive deliverables/BIN
	cp -a ilm-client/hive.md5 deliverables/BIN
	cp -a client/hive-patcher deliverables/BIN
	cp -a client/hive-patcher.md5 deliverables/BIN
	cp -a ilm-client/resetTimer_v1.0/hiveReset_v1_0.py deliverables/BIN
	cp -a ilm-client/server.key deliverables/BIN
	cp -a ilm-client/server.crt deliverables/BIN
	cp -a ilm-client/ca.crt deliverables/BIN
	cp -a honeycomb/honeycomb.py deliverables/BIN
	md5sum honeycomb/honeycomb.py > deliverables/BIN/honeycomb.py.md5
	mkdir -p deliverables/BIN/unpatched
	cp -a client/hived-*-*-unpatched deliverables/BIN/unpatched
	cp -a documentation/UsersGuide/* deliverables/DOC/
