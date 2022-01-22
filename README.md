# NTUSECURE-Ubuntu-Fix

The instructions for using NTUSECURE (NTU's school wifi) with Ubuntu is actually available online and mostly functional but required a few tweaks. 
It took me some time before I found out the problem, so I hope this repo saves you the hour I wasted!

This was tested on a Ubuntu 20.04 machine.

## Instructions

```
git clone https://github.com/callistachang/NTUSECURE-Ubuntu-Fix.git
```

```
python3 eduroam-linux-N-NTU.py
```

Running the script pulls up a GUI. Insert your username and password. 
If you are a student, enter YOUR_USERNAME@student.main.ntu.edu.sg as your username.

Next, go to your wifi settings, go to the Security tab and check the button that says "No CA certificate required".

You should be able to connect now!

Feel free to pull up an issue if it doesn't work for you. :)
