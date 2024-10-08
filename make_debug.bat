set CREDACASH_BUILD=%cd:\=/%
set CPPFLAGS=-Og -g3 -m64 -mthreads -fstack-protector-strong -Wno-misleading-indentation -Wno-deprecated-declarations
set CXXFLAGS=-Wno-deprecated-copy
set LDFLAGS=-static -fstack-protector
set LDLIBS=-lWs2_32 -lMswsock -lssp
cd source/3rdparty/Debug
make all
cd ../../..
cd source/cccommon/Debug
make all
cd ../../..
cd source/ccdll/Debug
make all
cd ../../..
cd source/cclib/Debug
make all
cd ../../..
cd source/ccnode/Debug
make all
cd ../../..
cd source/cctracker/Debug
make all
cd ../../..
cd source/ccwallet/Debug
make all
cd ../../..
echo CredaCash build done.
