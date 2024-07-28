# Ask for pid
echo "Enter the pid of the process you want to profile"
read pid
# Run the program
kcachegrind callgrind.out.$pid
