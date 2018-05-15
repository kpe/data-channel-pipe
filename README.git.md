

### sub tree merge for rawrtc-terminal-demo
Checkout the remote repo in its own branch

    git remote add rawrtc-terminal-demo https://github.com/rawrtc/rawrtc-terminal-demo.git
    git fetch rawrtc-terminal-demo
    git checkout -b -b rawrtc-terminal-demo rawrtc-terminal-demo/master

Pull the `c/src` directroy from the remote repo in the prefx subdirectory

    git checkout master
	git read-tree --prefix=src/ -u rawrt-terminal-demo:c/src

