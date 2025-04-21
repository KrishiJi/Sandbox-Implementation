# sandbox/sandbox_config.profile

# No network access
net none

# Private /tmp, /home, etc.
private

# Blacklist sensitive files
blacklist /etc/passwd
blacklist /etc/shadow
blacklist /root

# Read-only access to binaries
read-only /bin
read-only /usr

# Disable most system access
caps.drop all
seccomp

