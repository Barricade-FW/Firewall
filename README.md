# Barricade Firewall (NOT FINISHED)
## Description
An XDP Firewall that connects to a backbone running [this](https://github.com/Barricade-FW/Web-Server) application.

## Command Line Usage
The following command line arguments are supported:

* `--config -c` => Location to config file. Default => **/etc/bfw/bfw.conf**.
* `--list -l` => List all filtering rules currently implemented.
* `--help -h` => Print help menu for command line options.

## Configuration File Options
### Main
* `serverip` => The IP/hostname to the backbone server (running [this](https://github.com/Barricade-FW/Web-Server) application).
* `serverport` => The port to the backbone server.
* `usecache` => If we fail to connect to the backbone, use a local cached config file instead (default false).
* `key` => Base64 key generated from backbone.

## Configuration Example
Here's an example of a config:

```
{
    "serverip": "127.0.0.1",
    "serverport": 3020,
    "usecache": false,
    "key": "VGhpc2lzanVzdGFzaW1wbGV0ZXN0Zm9yYmFzZTY0ZW5jcnlwdGlvbg=="
}
```

## Building
Before building, ensure the `libconfig-dev` package is installed along with necessary building tools such as `llvm`, `clang`, and `libelf-dev`. For Debian/Ubuntu, you can install this with the following as root:

```
apt-get install libconfig-dev
```

You can use `git` and `make` to build this project. The following should work:

```
git clone --recursive https://github.com/Barricade-FW/Firewall
cd Firewall
make && make install
```

## Notes
### BPF For/While Loop Support
This project requires for/while loop support with BPF. Older kernels will not support this and output an error such as:

```
libbpf: load bpf program failed: Invalid argument
libbpf: -- BEGIN DUMP LOG ---
libbpf:
back-edge from insn 113 to 100

libbpf: -- END LOG --
libbpf: failed to load program 'xdp_prog'
libbpf: failed to load object '/etc/bfw/bfw_xdp.o'
```

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Creator.