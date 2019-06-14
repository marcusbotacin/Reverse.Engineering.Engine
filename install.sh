# Marcus Botacin
# Revenge installer

# Check calling
if [ "$0" != "bash" ]; then
    echo "You need to source this file";
    exit;
fi;

# Install dependencies
PACKAGE="indent"

# check package installed
dpkg -L $PACKAGE >/dev/null 2>/dev/null;

# check if something was found
if [ $? -gt 0 ]; then
    # install (debian-like only)
    echo "You need to install: "$PACKAGE
    sudo apt-get install $PACKAGE -y >/dev/null 2>/dev/null
fi;

# Set GDB History

# check history in file
grep -q "set history" ~/.gdbinit >/dev/null 2>/dev/null;

# check if something was found
if [ $? -gt 0 ]; then
    # set history
    echo 'set history save on' >> ~/.gdbinit;
fi;

# Set GDB source to revenge

# check if already set
grep -q "revenge.py" ~/.gdbinit >/dev/null 2>/dev/null;

# check if something was found
if [ $? -gt 0 ]; then
    # set history
    echo "source "$PWD"/revenge.py" >> ~/.gdbinit;
fi;

# Set GDB to quiet

# check if already set
grep -q "alias gdb" ~/.bashrc >/dev/null 2>/dev/null;

# check if something was found
if [ $? -gt 0 ]; then
    # set alias
    echo "alias gdb='gdb -q'" >> ~/.bashrc
fi;

# Set GDB to quit

# check if already set
grep -q "confirm off" ~/.gdbinit >/dev/null 2>/dev/null;

# check if something was found
if [ $? -gt 0 ]; then
    # set alias
    echo "set confirm off" >> ~/.gdbinit
fi;

# install pip3
# check package installed
PACKAGE="python3-pip"
dpkg -L $PACKAGE >/dev/null 2>/dev/null;

# check if something was found
if [ $? -gt 0 ]; then
    # install (debian-like only)
    echo "You need to install: "$PACKAGE
    sudo apt-get install $PACKAGE -y >/dev/null 2>/dev/null
fi;

# and google module
installed=`pip3 list 2>/dev/null | grep -c "google"`
if [ $installed -eq 0 ]; then
    sudo pip3 install google >/dev/null 2>/dev/null
fi;

# Finished!
echo "RevEngE is installed and configured!"
# Spawn a new shell with new env variables
exec bash
