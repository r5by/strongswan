# strongSwan Configuration #

## Overview ##

strongSwan is an OpenSource IPsec-based VPN solution.

This document is just a short introduction of the strongSwan **swanctl** command
which uses the modern [**vici**](src/libcharon/plugins/vici/README.md) *Versatile
IKE Configuration Interface*. The deprecated **ipsec** command using the legacy
**stroke** configuration interface is described [**here**](README_LEGACY.md).
For more detailed information consult the man pages, our new
[**documentation site**](https://docs.strongswan.org) and the legacy
[**wiki**](https://wiki.strongswan.org).


## Quickstart ##

Certificates for users, hosts and gateways are issued by a fictitious
strongSwan CA. In our example scenarios the CA certificate `strongswanCert.pem`
must be present on all VPN endpoints in order to be able to authenticate the
peers. For your particular VPN application you can either use certificates from
any third-party CA or generate the needed private keys and certificates yourself
with the strongSwan **pki** tool, the use of which will be explained in one of
the sections following below.


### Site-to-Site Case ###

In this scenario two security gateways _moon_ and _sun_ will connect the
two subnets _moon-net_ and _sun-net_ with each other through a VPN tunnel
set up between the two gateways:

    10.1.0.0/16 -- | 192.168.0.1 | === | 192.168.0.2 | -- 10.2.0.0/16
      moon-net          moon                 sun           sun-net

Configuration on gateway _moon_:

    /etc/swanctl/x509ca/strongswanCert.pem
    /etc/swanctl/x509/moonCert.pem
    /etc/swanctl/private/moonKey.pem

    /etc/swanctl/swanctl.conf:

        connections {
            net-net {
                remote_addrs = 192.168.0.2

                local {
                    auth = pubkey
                    certs = moonCert.pem
                }
                remote {
                    auth = pubkey
                    id = "C=CH, O=strongSwan, CN=sun.strongswan.org"
                }
                children {
                    net-net {
                        local_ts  = 10.1.0.0/16
                        remote_ts = 10.2.0.0/16
                        start_action = trap
                    }
                }
            }
        }

Configuration on gateway _sun_:

    /etc/swanctl/x509ca/strongswanCert.pem
    /etc/swanctl/x509/sunCert.pem
    /etc/swanctl/private/sunKey.pem

    /etc/swanctl/swanctl.conf:

        connections {
            net-net {
                remote_addrs = 192.168.0.1

                local {
                    auth = pubkey
                    certs = sunCert.pem
                }
                remote {
                    auth = pubkey
                    id = "C=CH, O=strongSwan, CN=moon.strongswan.org"
                }
                children {
                    net-net {
                        local_ts  = 10.2.0.0/16
                        remote_ts = 10.1.0.0/16
                        start_action = trap
                    }
                }
            }
        }

The local and remote identities used in this scenario are the
*subjectDistinguishedNames* contained in the end entity certificates.
The certificates and private keys are loaded into the **charon** daemon with
the command

    swanctl --load-creds

whereas

    swanctl --load-conns

loads the connections defined in `swanctl.conf`. With `start_action = trap` the
IPsec connection is automatically set up with the first plaintext payload IP
packet wanting to go through the tunnel.

### Host-to-Host Case ###

This is a setup between two single hosts which don't have a subnet behind
them.  Although IPsec transport mode would be sufficient for host-to-host
connections we will use the default IPsec tunnel mode.

    | 192.168.0.1 | === | 192.168.0.2 |
         moon                sun

Configuration on host _moon_:

    /etc/swanctl/x509ca/strongswanCert.pem
    /etc/swanctl/x509/moonCert.pem
    /etc/swanctl/private/moonKey.pem

    /etc/swanctl/swanctl.conf:

        connections {
            host-host {
                remote_addrs = 192.168.0.2

                local {
                    auth=pubkey
                    certs = moonCert.pem
                }
                remote {
                    auth = pubkey
                    id = "C=CH, O=strongSwan, CN=sun.strongswan.org"
                }
                children {
                    net-net {
                        start_action = trap
                    }
                }
            }
        }

Configuration on host _sun_:

    /etc/swanctl/x509ca/strongswanCert.pem
    /etc/swanctl/x509/sunCert.pem
    /etc/swanctl/private/sunKey.pem

    /etc/swanctl/swanctl.conf:

        connections {
            host-host {
                remote_addrs = 192.168.0.1

                local {
                    auth = pubkey
                    certs = sunCert.pem
                }
                remote {
                    auth = pubkey
                    id = "C=CH, O=strongSwan, CN=moon.strongswan.org"
                }
                children {
                    host-host {
                        start_action = trap
                    }
                }
            }
        }


### Roadwarrior Case ###

This is a very common case where a strongSwan gateway serves an arbitrary
number of remote VPN clients usually having dynamic IP addresses.

    10.1.0.0/16 -- | 192.168.0.1 | === | x.x.x.x |
      moon-net          moon              carol

Configuration on gateway _moon_:

    /etc/swanctl/x509ca/strongswanCert.pem
    /etc/swanctl/x509/moonCert.pem
    /etc/swanctl/private/moonKey.pem

    /etc/swanctl/swanctl.conf:

        connections {
            rw {
                local {
                    auth = pubkey
                    certs = moonCert.pem
                    id = moon.strongswan.org
                }
                remote {
                    auth = pubkey
                }
                children {
                    net-net {
                        local_ts  = 10.1.0.0/16
                    }
                }
            }
        }

Configuration on roadwarrior _carol_:

    /etc/swanctl/x509ca/strongswanCert.pem
    /etc/swanctl/x509/carolCert.pem
    /etc/swanctl/private/carolKey.pem

    /etc/swanctl/swanctl.conf:

        connections {
            home {
                remote_addrs = moon.strongswan.org

                local {
                    auth = pubkey
                    certs = carolCert.pem
                    id = carol@strongswan.org
                }
                remote {
                    auth = pubkey
                    id = moon.strongswan.org
                }
                children {
                    home {
                        local_ts  = 10.1.0.0/16
                        start_action = start
                    }
                }
            }
        }

For `remote_addrs` the hostname `moon.strongswan.org` was chosen which will be
resolved by DNS at runtime into the corresponding IP destination address.
In this scenario the identity of the roadwarrior `carol` is the email address
`carol@strongswan.org` which must be included as a *subjectAlternativeName* in
the roadwarrior certificate `carolCert.pem`.


### Roadwarrior Case with Virtual IP ###

Roadwarriors usually have dynamic IP addresses assigned by the ISP they are
currently attached to.  In order to simplify the routing from _moon-net_ back
to the remote access client _carol_ it would be desirable if the roadwarrior had
an inner IP address chosen from a pre-defined pool.

    10.1.0.0/16 -- | 192.168.0.1 | === | x.x.x.x | -- 10.3.0.1
      moon-net          moon              carol       virtual IP

In our example the virtual IP address is chosen from the address pool
`10.3.0.0/16` which can be configured by adding the section

    pools {
        rw_pool {
            addrs = 10.3.0.0/16
        }
    }

to the gateway's `swanctl.conf` from where they are loaded into the **charon**
daemon using the command

    swanctl --load-pools

To request an IP address from this pool a roadwarrior can use IKEv1 mode config
or IKEv2 configuration payloads. The configuration for both is the same

    vips = 0.0.0.0

Configuration on gateway _moon_:

    /etc/swanctl/x509ca/strongswanCert.pem
    /etc/swanctl/x509/moonCert.pem
    /etc/swanctl/private/moonKey.pem

    /etc/swanctl/swanctl.conf:

        connections {
            rw {
                pools = rw_pool

                local {
                    auth = pubkey
                    certs = moonCert.pem
                    id = moon.strongswan.org
                }
                remote {
                    auth = pubkey
                }
                children {
                    net-net {
                        local_ts  = 10.1.0.0/16
                    }
                }
            }
        }

        pools {
            rw_pool {
                addrs = 10.30.0.0/16
            }
        }

Configuration on roadwarrior _carol_:

    /etc/swanctl/x509ca/strongswanCert.pem
    /etc/swanctl/x509/carolCert.pem
    /etc/swanctl/private/carolKey.pem

    /etc/swanctl/swanctl.conf:

        connections {
            home {
                remote_addrs = moon.strongswan.org
                vips = 0.0.0.0

                local {
                    auth = pubkey
                    certs = carolCert.pem
                    id = carol@strongswan.org
                }
                remote {
                    auth = pubkey
                    id = moon.strongswan.org
                }
                children {
                    home {
                        local_ts  = 10.1.0.0/16
                        start_action = start
                    }
                }
            }
        }


### Roadwarrior Case with EAP Authentication ###

This is a very common case where a strongSwan gateway serves an arbitrary
number of remote VPN clients which authenticate themselves via a password
based *Extended Authentication Protocol* as e.g. *EAP-MD5* or *EAP-MSCHAPv2*.

    10.1.0.0/16 -- | 192.168.0.1 | === | x.x.x.x |
      moon-net          moon              carol

Configuration on gateway _moon_:

    /etc/swanctl/x509ca/strongswanCert.pem
    /etc/swanctl/x509/moonCert.pem
    /etc/swanctl/private/moonKey.pem

    /etc/swanctl/swanctl.conf:

        connections {
            rw {
                local {
                    auth = pubkey
                    certs = moonCert.pem
                    id = moon.strongswan.org
                }
                remote {
                    auth = eap-md5
                }
                children {
                    net-net {
                        local_ts  = 10.1.0.0/16
                    }
                }
                send_certreq = no
            }
        }

The  `swanctl.conf` file additionally contains a `secrets` section defining all
client credentials

        secrets {
            eap-carol {
                id = carol@strongswan.org
                secret = Ar3etTnp
            }
            eap-dave {
                id = dave@strongswan.org
                secret = W7R0g3do
            }
        }

Configuration on roadwarrior _carol_:

    /etc/swanctl/x509ca/strongswanCert.pem

    /etc/swanctl/swanctl.conf:

        connections {
            home {
                remote_addrs = moon.strongswan.org

                local {
                    auth = eap
                    id = carol@strongswan.org
                }
                remote {
                    auth = pubkey
                    id = moon.strongswan.org
                }
                children {
                    home {
                        local_ts  = 10.1.0.0/16
                        start_action = start
                    }
                }
            }
        }

        secrets {
            eap-carol {
                id = carol@strongswan.org
                secret = Ar3etTnp
            }
        }


### Roadwarrior Case with EAP Identity ###

Often a client EAP identity is exchanged via EAP which differs from the
external IKEv2 identity. In this example the IKEv2 identity defaults to
the IPv4 address of the client.

    10.1.0.0/16 -- | 192.168.0.1 | === | x.x.x.x |
      moon-net          moon              carol

Configuration on gateway _moon_:

    /etc/swanctl/x509ca/strongswanCert.pem
    /etc/swanctl/x509/moonCert.pem
    /etc/swanctl/private/moonKey.pem

    /etc/swanctl/swanctl.conf:

        connections {
            rw {
                local {
                    auth = pubkey
                    certs = moonCert.pem
                    id = moon.strongswan.org
                }
                remote {
                    auth = eap-md5
                    eap_id = %any
                }
                children {
                    net-net {
                        local_ts  = 10.1.0.0/16
                    }
                }
                send_certreq = no
            }
        }

        secrets {
            eap-carol {
                id = carol
                secret = Ar3etTnp
            }
            eap-dave {
                id = dave
                secret = W7R0g3do
            }
        }

Configuration on roadwarrior _carol_:

    /etc/swanctl/x509ca/strongswanCert.pem

    /etc/swanctl/swanctl.conf:

        connections {
            home {
                remote_addrs = moon.strongswan.org

                local {
                    auth = eap
                    eap_id = carol
                }
                remote {
                    auth = pubkey
                    id = moon.strongswan.org
                }
                children {
                    home {
                        local_ts  = 10.1.0.0/16
                        start_action = start
                    }
                }
            }
        }

        secrets {
            eap-carol {
                id = carol
                secret = Ar3etTnp
            }
        }


## Generating Certificates and CRLs ##

This section is not a full-blown tutorial on how to use the strongSwan **pki**
tool. It just lists a few points that are relevant if you want to generate your
own certificates and CRLs for use with strongSwan.


### Generating a CA Certificate ###

The pki statement

    pki --gen --type ed25519 --outform pem > strongswanKey.pem

generates an elliptic Edwards-Curve key with a cryptographic strength of 128
bits. The corresponding public key is packed into a self-signed CA certificate
with a lifetime of 10 years (3652 days)

    pki --self --ca --lifetime 3652 --in strongswanKey.pem \
               --dn "C=CH, O=strongSwan, CN=strongSwan Root CA" \
               --outform pem > strongswanCert.pem

which can be listed with the command

    pki --print --in strongswanCert.pem

    subject:  "C=CH, O=strongSwan, CN=strongSwan Root CA"
    issuer:   "C=CH, O=strongSwan, CN=strongSwan Root CA"
    validity:  not before May 18 08:32:06 2017, ok
               not after  May 18 08:32:06 2027, ok (expires in 3651 days)
    serial:    57:e0:6b:3a:9a:eb:c6:e0
    flags:     CA CRLSign self-signed
    subjkeyId: 2b:95:14:5b:c3:22:87:de:d1:42:91:88:63:b3:d5:c1:92:7a:0f:5d
    pubkey:    ED25519 256 bits
    keyid:     a7:e1:6a:3f:e7:6f:08:9d:89:ec:23:92:a9:a1:14:3c:78:a8:7a:f7
    subjkey:   2b:95:14:5b:c3:22:87:de:d1:42:91:88:63:b3:d5:c1:92:7a:0f:5d

If you prefer the CA private key and X.509 certificate to be in binary DER format
then just omit the `--outform pem` option. The directory `/etc/swanctl/x509ca`
contains all required CA certificates either in binary DER or in Base64 PEM
format. Irrespective of the file suffix the correct format will be determined
by strongSwan automagically.


### Generating a Host or User End Entity Certificate ###

Again we are using the command

    pki --gen --type ed25519 --outform pem > moonKey.pem

to generate an Ed25519 private key for the host `moon`. Alternatively you could
type

    pki --gen --type rsa --size 3072 > moonKey.der

to generate a traditional 3072 bit RSA key and store it in binary DER format.
As an alternative a **TPM 2.0** *Trusted Platform Module* available on every
recent Intel platform could be used as a virtual smartcard to securely store an
RSA or ECDSA private key. For details, refer to the TPM 2.0
[HOWTO](https://docs.strongswan.org/docs/5.9/tpm/tpm2.html).

In a next step the command

    pki --req --type priv --in moonKey.pem \
              --dn "C=CH, O=strongswan, CN=moon.strongswan.org" \
              --san moon.strongswan.org --outform pem > moonReq.pem

creates a PKCS#10 certificate request that has to be signed by the CA.
Through the [multiple] use of the `--san` parameter any number of desired
*subjectAlternativeNames* can be added to the request. These can be of the
form

    --san sun.strongswan.org     # fully qualified host name
    --san carol@strongswan.org   # RFC822 user email address
    --san 192.168.0.1            # IPv4 address
    --san fec0::1                # IPv6 address

Based on the certificate request the CA issues a signed end entity certificate
with the following command

    pki --issue --cacert strongswanCert.pem --cakey strongswanKey.pem \
                --type pkcs10 --in moonReq.pem --serial 01 --lifetime 1826 \
                --outform pem > moonCert.pem

If the `--serial` parameter with a hexadecimal argument is omitted then a random
serial number is generated. Some third party VPN clients require that a VPN
gateway certificate contains the *TLS Server Authentication* Extended Key Usage
(EKU) flag which can be included with the following option

    --flag serverAuth

If you want to use the dynamic CRL fetching feature described in one of the
following sections then you may include one or several *crlDistributionPoints*
in your end entity certificates using the `--crl` parameter

    --crl  http://crl.strongswan.org/strongswan.crl
    --crl "ldap://ldap.strongswan.org/cn=strongSwan Root CA, o=strongSwan,c=CH?certificateRevocationList"

The issued host certificate can be listed with

    pki --print --in moonCert.pem

    subject:  "C=CH, O=strongSwan, CN=moon.strongswan.org"
    issuer:   "C=CH, O=strongSwan, CN=strongSwan Root CA"
    validity:  not before May 19 10:28:19 2017, ok
               not after  May 19 10:28:19 2022, ok (expires in 1825 days)
    serial:    01
    altNames:  moon.strongswan.org
    flags:     serverAuth
    CRL URIs:  http://crl.strongswan.org/strongswan.crl
    authkeyId: 2b:95:14:5b:c3:22:87:de:d1:42:91:88:63:b3:d5:c1:92:7a:0f:5d
    subjkeyId: 60:9d:de:30:a6:ca:b9:8e:87:bb:33:23:61:19:18:b8:c4:7e:23:8f
    pubkey:    ED25519 256 bits
    keyid:     39:1b:b3:c2:34:72:1a:01:08:40:ce:97:75:b8:be:ce:24:30:26:29
    subjkey:   60:9d:de:30:a6:ca:b9:8e:87:bb:33:23:61:19:18:b8:c4:7e:23:8f

Usually, a Windows, OSX, Android or iOS based VPN client needs its private key,
its host or user certificate and the CA certificate.  The most convenient way
to load this information is to put everything into a PKCS#12 container:

    openssl pkcs12 -export -inkey carolKey.pem \
                   -in carolCert.pem -name "carol" \
                   -certfile strongswanCert.pem -caname "strongSwan Root CA" \
                   -out carolCert.p12

The strongSwan **pki** tool currently is not able to create PKCS#12 containers
so that **openssl** must be used.


### Generating a CRL ###

An empty CRL that is signed by the CA can be generated with the command

    pki --signcrl --cacert strongswanCert.pem --cakey strongswanKey.pem \
                  --lifetime 30 > strongswan.crl

If you omit the `--lifetime` option then the default value of 15 days is used.
CRLs can either be uploaded to a HTTP or LDAP server or put in binary DER or
Base64 PEM format into the `/etc/swanctl/x509crl` directory from where they are
loaded into the **charon** daemon with the command

    swanctl --load-creds


### Revoking a Certificate ###

A specific end entity certificate is revoked with the command

    pki --signcrl --cacert strongswanCert.pem --cakey strongswanKey.pem \
                  --lifetime 30 --lastcrl strongswan.crl \
                  --reason key-compromise --cert moonCert.pem > new.crl

Instead of the certificate file (in our example moonCert.pem), the serial number
of the certificate to be revoked can be indicated using the `--serial`
parameter. The `pki --signcrl --help` command documents all possible revocation
reasons but the `--reason` parameter can also be omitted. The content of the new
CRL file can be listed with the command

    pki --print --type crl --in new.crl

    issuer:   "C=CH, O=strongSwan, CN=strongSwan Root CA"
    update:    this on May 19 11:13:01 2017, ok
               next on Jun 18 11:13:01 2017, ok (expires in 29 days)
    serial:    02
    authKeyId: 2b:95:14:5b:c3:22:87:de:d1:42:91:88:63:b3:d5:c1:92:7a:0f:5d
    1 revoked certificate:
      01: May 19 11:13:01 2017, key compromise


### Local Caching of CRLs ###

The `strongswan.conf` option

    charon {
        cache_crls = yes
    }

activates the local caching of CRLs that were dynamically fetched from an
HTTP or LDAP server.  Cached copies are stored in `/etc/swanctl/x509crl` using a
unique filename formed from the issuer's *subjectKeyIdentifier* and the
suffix `.crl`.

With the cached copy the CRL is immediately available after startup.  When the
local copy has become stale, an updated CRL is automatically fetched from one of
the defined CRL distribution points during the next IKEv2 authentication.


### Connect gdb Debugger to Test Suite ###

Rich examples of applying strongswan IPsec in practice are provided in `cd testing` folder. It
can be useful for newbie developer to follow the setups there and be able to step into the code 
implementation while plugin one's own debugger with hand. `testing/README` provides basic
introductions of building, loading and verifying all test cases. However, to connect gdb to 
gdbserver running inside these VM's, the following settings should be prepared:

1) Adding supporting linux packets (for Ubuntu 22.04) in `testing/scripts/build-baseimage`:
```bash
INC=$INC,libpcap-dev,nmap,gdbserver 
```
2) Update filesystem automount point for default host image in `testing/hosts/default/etc/fstab`:
```bash
   /hostsrc /root/strongswan 9p trans=virtio,version=9p2000.L 0 0    
```
Then, update iptable rules to allow _gdbserver_ to operate in `testing/hosts/iptables.rules`:
```bash
# Allow incoming connections on port 1234 for GDB server
-A INPUT -p tcp --dport 1234 -j ACCEPT
-A OUTPUT -p tcp --sport 1234 -j ACCEPT
```
3) Modify _libvirtd_ hosts' configurations in `testing/config/kvm` so that the VM filesystem
may recognize the strongswan source later on:
```xml
    <filesystem type='mount' accessmode='mapped'>
      <source dir='/var/run/kvm-strongswan'/>
      <target dir='/hostsrc'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x09' function='0x0'/>
    </filesystem>
```
4) Modify the actual `start-testing` and `stop-testing` shell scripts to enable gdbserver related
tasks. (skipped, use `git`to verify)

After these modification, rebuild testing environment

    sudo ./make-testting

> Sometimes building guest images may fail due to lazy unmounting the previously mounted points.
> Turnoff other configurations but only `: ${ENABLE_BUILD_GUESTIMAGES=yes}` in `testing/testing.conf` file
> and remake the testing to solve this problem

Tips:

* If somehow the building procedure fails in between stages, check the following to make sure
a clear-stage for next try-out:

```bash
    # 1) Clear leftover VM's
    $ virsh list   # check if all vm's are shutdown
    $ virsh destroy xxx  # destroy whatever remains..
    
    # 2) Umount leftovers
    $ mount  # check if all mount points are successfully detached
    $ umount  xxx  # unmount the unwanted from BOTTOM TO TOP (avoid "mount point is busy" someshit)
```

* Don't forget to put `sudo` in front of all testing related command, and don't forget
to shutdown the test environment by issuing command `sudo ./stop-testing`. 

* To avoid strict host key checking whenever connect to the VM's, modify the `~/.ssh/config` file as following:
```bash
    Host xxx
        StrictHostKeyChecking no
        
    # Then, ssh to xxx shouldn't let you choose `yes` or `no`
    $ ssh root@xxx
```

Now its ready for you to connect any remote VM's via gdb. Take `testing/tests/ike2/net2net-psk` as
an example, issue the following commands in order:
```bash
    # on host
    $ virsh list # verify no testing environment has started yet
    $ sudo ./start-testing  # start testing env
    $ sudo scripts/load-testconfig ikev2/net2net-psk  # load the configuration
    $ ssh root@moon
    
    # on guest vm `moon`: 
    # BEFORE following gdbserver command, pls follow steps specified in:
    # ikev2/net2net-psk/console.log
    # for each VM hosts, for example, you may see user stories like:
    # PRE-TEST
    # moon# iptables-restore < /etc/iptables.rules
    # sun# iptables-restore < /etc/iptables.rules
    # moon# cd /etc/swanctl; rm rsa/* x509/* x509ca/*
    # sun# cd /etc/swanctl; rm rsa/* x509/* x509ca/*
    # ...
    $ gdbserver :1234 swanctl --initiate --child net-net
    
    # on host (should be able to connect the server)
    $ gdb /usr/local/sbin/swanctl -ex "target extended-remote 192.168.0.1:1234"
    
    # feel free to mess up with your gdb command line tool to step through code...
```

> Navigate the [here](https://www.strongswan.org/testresults.html) for all available strongswan test cases.

Use wireshark to capture the IPsec packets passed on-and-off between VM's, for example, you may
order wireshark to sniff on `moon-eth0` in the above test case, and filter packets via:

```bash
    ip.addr==192.168.0.1 and (isakmp or esp)
```

### Some Interesting Debug Information ###

There are multiple ways of starting `charon` IKE deamon for strongswan, the recommended way (up
to the time this article is written) is via `vici` interface plugin:

```bash
  ls /lib/systemd/system |grep strongswan
  
  cat /lib/systemd/system/strongswan.service
```

The output shows:

```bash
[Unit]
Description=strongSwan IPsec IKEv1/IKEv2 daemon using swanctl
After=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/sbin/charon-systemd
ExecStartPost=/usr/local/sbin/swanctl --load-all --noprompt
ExecReload=/usr/local/sbin/swanctl --reload
ExecReload=/usr/local/sbin/swanctl --load-all --noprompt
Restart=on-abnormal

[Install]
WantedBy=multi-user.target
Alias=strongswan-swanctl.service
```

or through legacy `ipsec` shell script: 

```bash
  # Call: $ cat /lib/systemd/system/strongswan-starter.service
[Unit]
Description=strongSwan IPsec IKEv1/IKEv2 daemon using ipsec.conf
After=syslog.target network-online.target

[Service]
ExecStart=/usr/local/sbin/ipsec start --nofork
Restart=on-abnormal

[Install]
WantedBy=multi-user.target
```

Inspect into the `ipsec` script shows:

```bash
#! /bin/sh 
# prefix command to run stuff from our programs directory
...
# set daemon name 
[ -z "$DAEMON_NAME" ] && DAEMON_NAME="charon"

IPSEC_DIR="/usr/local/libexec/ipsec"
IPSEC_STARTER="${IPSEC_DIR}/starter"

case "$1" in
...
start)  
        shift   
        if [ -d /var/lock/subsys ]; then 
                touch /var/lock/subsys/ipsec 
        fi      
        exec $IPSEC_STARTER --daemon $DAEMON_NAME "$@" 
        ;;
...
```

### Clion IDE Integration ###

Several changes have to be made before using CLion as our development IDE. Open `setting->Build,Execution,Deployment->Makefile`
and modify the following in `Commands` window:

```bash
    which autoreconf >/dev/null && autoreconf --install --force --verbose "${PROJECT_DIR:-..}" 2>&1; /bin/sh "${PROJECT_DIR:-..}/configure" --enable-systemd --enable-swanctl
```

This helps prepare the project makefile building environment for `systemd` service, so that
later when we inspect `charon-systemd.c`, CLion editor won't complain about "The file does not belong to any project target..."

### Logging ###

To instrument charon and enable the full [logging](https://docs.strongswan.org/docs/6.0/config/logging.html) capability of strongswan, the compiling option should be turned on firstly,

```bash
# configure.ac

# ===========================
#  set up compiler and flags
# ===========================

if test -z "$CFLAGS"; then
	CFLAGS="-g -O0 -DDEBUG_LEVEL=4"
fi

```

Then recompile the root image following README in `tests` folder and edit `strongswan.conf` to configure logging for a specific target.

For example, if we want to verify logging details in `moon` host during the test case `net2net-gw`, we need to update the `testing/tests/ikev2/net2net-gw/hosts/moon/etc/strongswan.conf` file
as follows:

```bash
# /etc/strongswan.conf - strongSwan configuration file

swanctl {
  load = pem pkcs1 x509 revocation constraints pubkey openssl random
}

charon-systemd {
  load = random nonce aes sha1 sha2 hmac kdf pem pkcs1 x509 revocation curve25519 gmp curl kernel-netlink socket-default updown vici
}

charon {
  filelog {
     charon{
        path = /var/log/charon.log
	    time_format = %b %e %T
	    ike_name = yes
        append = no
        default = 2
        flush_line = yes
     }
     stderr {
	time_format = %b %e %T
	dmn = 4
	ike = 2
	knl = 3
     }
  }
}
```

Then issue `sudo ./do-tests ikev2/net2net-gw` or its sub-procedure `sudo scripts/load-testconfig ikev2/net2net-gw` shall upload this configuration upto the VM.