

# To Build
Build dependencies in a local prefix under `./build/prefix`

    ./make-dependencies.sh

Add the custom prefix to pkg-config search PATH

	export PKG_CONFIG_PATH=${PWD}/build/prefix/lib/pkgconfig
	export LD_LIBRARY_PATH=${PWD}/build/prefix/lib

Now build with CMake 3.2+

	cd build
	cmake -DCMAKE_INSTALL_PREFIX=${PWD}/prefix ..
	make install



# Signaling Server
To start it

	python3 -m venv .venv
	. .venv/bin/activate
	pip install -r requirements.txt
	python signaliing-server.py

To run the unit tests (for the signaling server)

    npm install mocha chai
    
and open the `unit-tests.html` in a browser.

# How to use the data channel pipe
To pipe the stdout and stdion over a WebRTC DataChannel, you could use the above signaling
server for establishing a peer connection between you WebRTC client and a running instance
of the `rawrtc-data-channel` binary built in the previous step:

 1. start the signaling server
 2. start the pipe process (passing the WS address of the signalling server)
 
     ./build/prefix/bin/rawrtc-datachannel-pipe ws://127.0.0.1:9765/test
     
 3. in your client establish a second WS connection to the signalling server, and use it to
 establish an WebRTC PeerConnection with the just started console application.
 
     python signaling-server.py
