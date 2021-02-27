# FireMillTor
`DISCLAIMER`

The information contained in this repository(repo) is for educational purposes ONLY! The authors or contributors DO NOT hold any responsibility for any misuse or damage of the information and/or code provided in repo.

`DISCLAIMER`

## Setup VPS
1. Login into root account
1. `passwd`
    1. Change password
1. `adduser <username>`
1. `usermod -a -G sudo holdmybeertor`
    1. Create a standard user with `sudo` privileges
1. Open a new temrinal
1. `ssh-copy-id <username>@<TOR IP addr>`
    1. Enter IP addr
1. `sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config`
    1. Disable ROOT login via SSH
1. `sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config`
    1. Enforce key based auth
1. `systemctl restart sshd`
1. `exit`
1. `ssh <username>@<TOR IP addr>`
1. `sudo su`
    1. Enter password
1. `apt update -y && apt upgrade -y && apt dist-upgrade -y && reboot`

## Setup Ansible playbook
1. `vim hosts.ini` and add VPS IP address under `[tor]`
1. `vim group_vars/all.yml` and set:
    1. `hostname` - Set the hostname of the machine
    1. `timezone` - Set the timezone for the machine
    1. `monitoring_interface` - Interface to monitor for network traffic
1. `cp group_vars/loggign_tools.yml.example group_vars/loggign_tools.yml`
1. `group_vars/loggign_tools.yml` and set:
    1. `logstash_server` -  Set to the IP/FQDN of Logstash and port for Beats
1. If you plan on implementing client certs for Filebeat logging
    1. Copy client cert to `conf/tls/client_cert`
    1. Copy client key to `conf/tls/client_cert`
    1. Copy root CA to `conf/tls/root_ca`
    1. Set `client_cert` to `True` in `group_vars/loggign_tools.yml`
1. 

## Run Ansible playbook
1. `ansible-playbook -i hosts.ini deploy_tor_node.yml -u <username> -K`
    1. Enter password

## Supported OSes
* Ubuntu Server 20.04

## Refereneces
### Ansible
* [ansible.builtin.apt_repository – Add and remove APT repositories](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/apt_repository_module.html)
* [ansible.builtin.apt_key – Add or remove an apt key](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/apt_key_module.html)
* [ansible.builtin.unarchive – Unpacks an archive after (optionally) copying it from the local machine](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/unarchive_module.html)
* [community.general.make – Run targets in a Makefile](https://docs.ansible.com/ansible/latest/collections/community/general/make_module.html)
* [Setting hostname with Ansible](https://www.derpturkey.com/setting-host-with-ansible-in-ubuntu/)
* [Installing specific apt version with ansible](https://stackoverflow.com/questions/36150362/installing-specific-apt-version-with-ansible)
* [How to loop over this dictionary in Ansible?](https://stackoverflow.com/questions/42167747/how-to-loop-over-this-dictionary-in-ansible)
* [Ansible - community.general.capabilities – Manage Linux capabilities](https://docs.ansible.com/ansible/latest/collections/community/general/capabilities_module.html)
* [How to add user and group without a password using Ansible?](https://stackoverflow.com/questions/36290485/how-to-add-user-and-group-without-a-password-using-ansible/36371379)
* [Failed to set permissions on the temporary files Ansible needs to create when becoming an unprivileged user #55](https://github.com/georchestra/ansible/issues/55)
* [Understanding privilege escalation: become](https://docs.ansible.com/ansible/latest/user_guide/become.html#becoming-an-unprivileged-user%22)
* [How to fix the /usr/bin/python: not found error in Ansible](https://www.toptechskills.com/ansible-tutorials-courses/how-to-fix-usr-bin-python-not-found-error-tutorial/)
* [ansible.builtin.group – Add or remove groups](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/group_module.html)
* [community.general.docker_compose – Manage multi-container Docker applications with Docker Compose](https://docs.ansible.com/ansible/latest/collections/community/general/docker_compose_module.html)
* [ansible.builtin.systemd – Manage services](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/systemd_module.html)
* [How to add user and group without a password using Ansible?](https://stackoverflow.com/questions/36290485/how-to-add-user-and-group-without-a-password-using-ansible/36371379)
* [ansible.builtin.copy – Copy files to remote locations](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/copy_module.html)
* [ansible.builtin.wait_for – Waits for a condition before continuing](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/wait_for_module.html)
* []()

### Suricata 
* [apt install linux-headers-$(uname -r) in ansible](https://www.reddit.com/r/ansible/comments/bzdd7q/apt_install_linuxheadersuname_r_in_ansible/)
* [suricata-pf_ring-init.sh](https://raw.githubusercontent.com/CptOfEvilMinions/BlogProjects/master/suricatav5-pf_ring/conf/suricata/suricata-pf_ring-init.sh)
* [default_suricata_pf-ring](https://raw.githubusercontent.com/CptOfEvilMinions/BlogProjects/master/suricatav5-pf_ring/conf/suricata/default_suricata_pf-ring)
* [How to Install Kernel Headers in Ubuntu and Debian](https://www.tecmint.com/install-kernel-headers-in-ubuntu-and-debian/)
* [Github - ntop/PF_RING](https://github.com/ntop/PF_RING)
* [PF_RING - Installing from GIT](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html)
* [How to install autoconf](https://askubuntu.com/questions/290194/how-to-install-autoconf)
* [Github issue - "libtoolize not found" - linux dependency](https://github.com/beakerbrowser/beaker/issues/54)
* [PF_RING FT (Flow Table)](https://www.ntop.org/products/packet-capture/pf_ring/pf_ring-ft-flow-table/)
* [Installation of Suricata stable with PF RING (STABLE) on Ubuntu server 12.04](https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Installation_of_Suricata_stable_with_PF_RING_(STABLE)_on_Ubuntu_server_1204)
* [Detecting intruders with Suricata = ](https://www.admin-magazine.com/Articles/Detecting-intruders-with-Suricata/(offset)/3)
* [Suricata - Controlling which rules are used](https://suricata.readthedocs.io/en/suricata-5.0.3/rule-management/suricata-update.html#controlling-which-rules-are-used)
* [Suricata Update Documentation - Example Configuration File (/etc/suricata/update.yaml)](https://readthedocs.org/projects/suricata-update/downloads/pdf/latest/)
* [Github gist - Suricata v5.0.3 init.d and default config for pf_ring](https://gist.github.com/CptOfEvilMinions/5a35409d6cc57e5bc503dca8fe3413a2)
* [Suricata](https://www.cnblogs.com/zlslch/p/7382190.html)
* [Setting up the Suricata IDPS](https://ev1z.be/2016/11/27/setting-up-the-suricata-idps/)
* [Bug#839146: suricata failures with systemd](https://groups.google.com/g/linux.debian.bugs.dist/c/03x0Gt3a_y4?pli=1)
* [Github issuee - pf_ring init script doesn't load drivers after rebuilding them upon kernel update. #102](https://github.com/ntop/PF_RING/issues/102)
* [Github - hultdin/nsmfoo - 00. Suricata + Barnyard2 + Snorby == True](https://github.com/hultdin/nsmfoo)
* [nDPI - Quick Start Guide](https://www.ntop.org/wp-content/uploads/2013/12/nDPI_QuickStartGuide.pdf)
* []()

### Zeek 
* [Installing Bro IDS on Fedora 25](https://www.vultr.com/docs/installing-bro-ids-on-fedora-25)
* [BroControl](https://www.bro.org/sphinx/components/broctl/README.html)
* [How To Install EPEL Repo on a CentOS and RHEL 7.x](https://www.cyberciti.biz/faq/installing-rhel-epel-repo-on-centos-redhat-7-x/)
* [Writing Bro Plugins](https://www.bro.org/sphinx-git/devel/plugins.html)
* [extract-all-files.bro](https://www.bro.org/sphinx/scripts/policy/frameworks/files/extract-all-files.bro.html)
* [stats.bro](https://www.bro.org/sphinx/scripts/policy/misc/stats.bro.html)
* [Bro Package Manager: list of packages](http://blog.bro.org/2017/06/bro-package-manager-list-of-packages.html)
* [Detecting Malicious SMB Activity Using Bro](https://www.sans.org/reading-room/whitepapers/detection/detecting-malicious-smb-activity-bro-37472)
* [MIME Types List](https://www.freeformatter.com/mime-types-list.html)
* [THREAT HUNTING WITH BRO](https://sqrrl.com/threat-hunting-bro/)
* [Binary Packages for Bro Releases](https://www.bro.org/download/packages.html)
* [Zeek - Installing](https://docs.zeek.org/en/current/install/install.html#installing-from-source)
* [PART 1: INSTALL/SETUP ZEEK + PF_RING ON UBUNTU 18.04 ON PROXMOX 5.3 + OPENVSWITCH](https://holdmybeersecurity.com/2019/04/03/part-1-install-setup-zeek-pf_ring-on-ubuntu-18-04-on-proxmox-5-3-openvswitch/)
* [Github - CptOfEvilMinions/BlogProjects/suricatav5-pf_ring/roles/setup_pf_ring.yml](https://github.com/CptOfEvilMinions/BlogProjects/blob/master/suricatav5-pf_ring/roles/setup_pf_ring.yml)
* [Zeek (Bro) Module](https://www.elastic.co/guide/en/beats/filebeat/7.10/filebeat-module-zeek.html)
* [Zeek Package Manager - Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html#installation)
* [ZEEKURITY ZEN – PART I: HOW TO INSTALL ZEEK ON CENTOS 8](https://www.ericooi.com/zeekurity-zen-part-i-how-to-install-zeek-on-centos-8/)
* [How to run systemd service as specific user and group in Linux](https://www.golinuxcloud.com/run-systemd-service-specific-user-group-linux/)
* [Installing Zeek 3.1.4 on Ubuntu 20.04](https://www.securitynik.com/2020/06/installing-zeek-314-on-ubuntu-2004.html)
* [Bro service config](https://github.com/CptOfEvilMinions/FireMillTor/commit/d9a28044ffeea71773a1cd55726b5e9a24d14737#diff-b775f9a5e5dc679ddda19ea38ab567ce6b6a477503d6f6c74564c147c6d635e2)
* [Zeek (Bro) Network Security Monitor](https://docs.humio.com/docs/security/zeek/)
* [zeek/scripts/site/local.zeek](https://github.com/zeek/zeek/blob/master/scripts/site/local.zeek)
* []()

### TOR
* [Github - Tor config](https://github.com/jgamblin/tor/blob/master/torrc)
* [How to set up a Tor Exit Node & sniff traffic.](https://medium.com/@omaidfaizyar/how-to-set-up-a-tor-exit-node-sniff-traffic-301fca7548b)
* []()

### Osquery
* [Ansible - yum](https://docs.ansible.com/ansible/latest/modules/yum_module.html)
* [JSON linter](https://jsonlint.com/)
* [OSQuery docs - config](https://osquery.readthedocs.io/en/stable/deployment/configuration/)
* [OSQuery docs - syslog](https://osquery.readthedocs.io/en/stable/deployment/syslog/)
* [Github - OSQuery syslog issue](https://github.com/facebook/osquery/issues/1964)
* [Downloading & Installing Osquery](https://osquery.io/downloads/official/4.5.1)
* [Osquery module](https://www.elastic.co/guide/en/beats/filebeat/7.9/filebeat-module-osquery.html)
* []()

### Docker 
* [Install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
* [community.general.docker_image – Manage docker images](https://docs.ansible.com/ansible/latest/collections/community/general/docker_image_module.html)
* []()


### Filebeat
* [Repositories for APT and YUM](https://www.elastic.co/guide/en/beats/filebeat/current/setup-repositories.html)
* [Install old beats version from repository](https://discuss.elastic.co/t/install-old-beats-version-from-repository/69073)
* [Filebeat sets type automatically #476](https://github.com/elastic/beats/issues/476)
* [Changes to the output fields](https://www.elastic.co/guide/en/beats/filebeat/6.8/migration-changed-fields.html)
* [Load external configuration files](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-configuration-reloading.html)
* [Configure inputs](https://www.elastic.co/guide/en/beats/filebeat/current/configuration-filebeat-options.html)
* [Zeek - Configure Filebeat](https://docs.humio.com/integrations/security-and-incident-management/zeek/)
* []()