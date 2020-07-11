# Barricade Firewall (NOT FINISHED)
## Description
An XDP Firewall that optionally connects to a backbone running [this](https://github.com/Barricade-FW/Web-Server) application.

## Command Line Usage
The following command line arguments are supported:

* `--config -c` => Location to config file. Default => **/etc/bfw/bfw.conf**.
* `--list -l` => List all filtering rules currently implemented.
* `--help -h` => Print help menu for command line options.

## Startup Configuration File Options
* `interface` => The interface for the XDP program to bind to (e.g. "ens18").
* `serverip` => The IP/hostname to the backbone server (running [this](https://github.com/Barricade-FW/Web-Server) application).
* `serverport` => The port to the backbone server.
* `key` => Base64 key generated from backbone.

**Note** => These are the config options you'll want to set when starting up the firewall and connecting to the backbone for the first time.

**Note** - The backbone will hold the *entire* config. This means the `interface`, `serverip`, `serverport`, and `key` items will be replaced with the values retrieved from the backbone.

## Startup Configuration Example
Here's an example of a config for starting up the XDP firewall for the first time and connecting to the backbone to retrieve all settings:

```
{
    "interface": "ens18",
    "serverip": "127.0.0.1",
    "serverport": 3020,
    "key": "VGhpc2lzanVzdGFzaW1wbGV0ZXN0Zm9yYmFzZTY0ZW5jcnlwdGlvbg=="
}
```

Assuming the connection to the backbone is established and the key is correct, it will retrieve filters and additional options from the backbone. We also set the interface here so the XDP program attaches correctly and doesn't stop the program.

## Configuration Example Without Backbone
Here's an example of a config that doesn't connect to the backbone to sync settings:

```
{
    "interface": "ens18",
    "updatetime": 15,
    "stats": true,

    "filters": [
        {
            "enabled": true,
            "action": 1
        }
    ]
}
```

## Building
Before building, ensure necessary building tools are installed such as `llvm`, `clang`, `libelf-dev`, and `cmake`.

You can use `git` and `make` to build this project. The following should work:

```
git clone --recursive https://github.com/Barricade-FW/Firewall.git
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