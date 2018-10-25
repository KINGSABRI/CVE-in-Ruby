# CVE-in-Ruby 

![](Rubyfu_initiative.png)

It's a repository to import public exploits to be written in Ruby without Metasploit complication 

# Why not Metasploit? 
1. To educate people how to write exploits using Ruby 
2. To Write exploit for CVEs that doesn't have exploit in a *simple way*
3. To avoid Metasploit complications. *But we still LOVE Metasploit*
4. To list a common exploit that we face in PT that may or may not exist in Metasploit
5. To Centeralize exploits that written in other languages to be written in Ruby

# How to contribute? 
1. Fork it
2. Create your new exploit branch (`git checkout -b CVE-2016-xxxx`)
3. Create a sub-directory for your exploit with the same CVE number (`mkdir CVE-2016-xxxx`)
4. Create your `CVE-2016-xxx_exploit.rb` and `README.md` files. *Naming convsion is required*
5. Add the vulnerable application to the sub-directory `CVE-2016-xxxx`. ***Recommended!***
6. Commit your changes (`git commit add *`)
7. Commit your changes (`git commit -m "CVE-2016-xxxx | Application name"`)
8. Push to the branch (`git push origin CVE-2016-xxxx`)
9. Cerate new Pull Request (PR)

# Notes
- It's good to add some comment in your code when needed
- It's good to add a PoC if you'd like.
- Add usefull references in README.md file 
- Check and copy *CVE-0000-0000* example
