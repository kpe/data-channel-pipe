

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

To run the unit tests

    npm install mocha chai
    
and open the `unit-tests.html` in a browser.
