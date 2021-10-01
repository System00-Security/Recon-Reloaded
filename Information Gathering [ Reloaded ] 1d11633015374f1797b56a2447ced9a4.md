# Information Gathering [ Reloaded ]

## Information Gathering & Scaning for sensitive information

- **Whois Lookup**
    
    To Check Other websites registered by the registrant of the site (reverse check on the registrant, email address, and telephone), and in-depth investigation of the sites found.
    
    ```bash
    whois target.tld
    ```
    
- **Website Ip**
    
    For collecting Server Side Information sometime we need the ip of the website , but many website usage cdn to protect them here is conventional way to bypass the cdn.If Cdn is Not available on the target just use ping to find the ip of the website.
    
    ```bash
    ping uber.com
    ```
    
    **If  cdn is available**
    
    ```bash
    http://crimeflare.org:82/cfs.html #to find the real ip behind the cloudflare
    or
    https://github.com/gwen001/pentest-tools/blob/master/cloudflare-origin-ip.py
    or
    https://censys.io/
    ```
    
- **Asset Discovery**
    - **Horizontal domain correlation**
        
        Most of The time we focus on subdomains ,but they skipout the other half aka Horizontal domain correlation . 
        
        what is Horizontal domain correlation?
        
        horizontal domain correlation is a process of finding other domain names, which have a different second-level domain name but are related to the same entity
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled.png)
        
        Firstly, let's think about it. We cannot rely on a syntactic match as we did in the previous step. Potentially, [abcabcabc.com](http://abcabcabc.com/) and [cbacbacba.com](http://cbacbacba.com/) can be owned by the same entity. However, they don't match syntactically. For this purpose, we can use WHOIS data. There are some reverse WHOIS services which allow you to search based on the common value from WHOIS database. Lets run whois for sony.com
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%201.png)
        
        Now lets do a reverse whois lookup with the registrant email, we can do a reverse whois lookup using [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/)
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%202.png)
        
        More reverse Whois site
        
        ```python
        https://domaineye.com/reverse-whois
        https://www.reversewhois.io/
        ```
        
        We can make this one cli mode
        
        [https://gist.github.com/JoyGhoshs/80543553f7442271fbc1092a9de08385](https://gist.github.com/JoyGhoshs/80543553f7442271fbc1092a9de08385)
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%203.png)
        
    - **Subdomain Enumeration / Vertical domain correlation**
        - Passive Enumeration
            
            There are so many tools available on the internet to gather subdomain from many different source.But We Also Can use those various passive subdomain collection source to find subdomain manually.
            
            - **Google Dorking**
            
            ```
            site:*.target.tld
            
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%204.png)
            
            Its Hard To go page to page to and copy those subdomain ,lets make it cli based
            
            ```bash
            #!/usr/bin/bash
            domain=$1
            agent="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36"
            curl -s -A $agent "https://www.google.com/search?q=site%3A*.$domain&start=10" | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | grep $domain | sort -u
            curl -s -A $agent "https://www.google.com/search?q=site%3A*.$domain&start=20" | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | grep $domain | sort -u
            curl -s -A $agent "https://www.google.com/search?q=site%3A*.$domain&start=30" | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | grep $domain | sort -u
            curl -s -A $agent "https://www.google.com/search?q=site%3A*.$domain&start=40" | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | grep $domain | sort -u
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%205.png)
            
            You can make the script more simple with loop on start parameter 10 means page one 20 means page to and this goes on.
            
            - **Bing Dorking**
            
            ```
            site:uber.com
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%206.png)
            
            [**Shodan.io**](http://shodan.io)
            
            We can enumerate subdomain from shodan using the search web interface or using python based cli client.
            
            **Web-Client Dork-**
            
            > hostname:"target.tld"
            > 
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%207.png)
            
            **Cli-Client** 
            
            ```bash
            shodan init your_api_key #set your api key on client
            shodan domain domain.tld 
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%208.png)
            
            - **Hackertarget.com**
            
            ```
            https://hackertarget.com/find-dns-host-records/
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%209.png)
            
            Hackertarget also has a api , we can use it on our cli without any auth-token or key
            
            ```bash
            curl -s https://api.hackertarget.com/hostsearch/?q=uber.com |grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+'
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2010.png)
            
            - **Crt.sh**
            
            To find subdomain from certificate transparency.
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2011.png)
            
            lets make oneliner for this so we can grub it from cli.
            
            ```bash
            curl -s "https://crt.sh/?q=%25.target.tld&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2012.png)
            
            its boring for you to get through these many screenshots lets just create oneliner for other source to get subdomains of target domain from cli.
            
            - [riddler.io](http://riddler.io)
            
            ```bash
            curl -s "https://riddler.io/search/exportcsv?q=pld:domain.com" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u
            ```
            
            - [subbuster.cyberxplore.com](http://subbuster.cyberxplore.com)
            
            ```bash
            curl "https://subbuster.cyberxplore.com/api/find?domain=domain.tld" -s | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+"
            ```
            
            - certspotter
            
            ```bash
            curl -s "https://certspotter.com/api/v1/issuances?domain=domain.com&include_subdomains=true&expand=dns_names" | jq .[].dns_names | tr -d '[]"\n ' | tr ',' '\n'
            ```
            
            **SAN [** Subject Alternate Name **] domain extraction**
            
            These are little sample of the source to gather subdomains now lets know about SAN based subdomain enumeration S.A.N stands for Subject Alternate Name, The Subject Alternative Name (SAN) is an extension to the X.509 specification that allows to specify additional host names for a single SSL certificate.
            
            Lets Write a Bash Script to extracts domain from ssl certificate using openssl.
            
            ```bash
            sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
                N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
                openssl x509 -noout -text -in <(
                    openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
                        -connect sony.com:443 ) )
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2013.png)
            
            lets filter only domain from this result using grep
            
            ```bash
            sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
                N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
                openssl x509 -noout -text -in <(
                    openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
                        -connect sony.com:443 ) ) | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+'
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2014.png)
            
            **DNS enumeration using Cloudflare**
            
            Its a bit complicated process because you need a cloudflare account to use this python3 script. this script use cloudflare to extract subdomains.
            
            ```bash
            wget https://raw.githubusercontent.com/appsecco/bugcrowd-levelup-subdomain-enumeration/master/cloudflare_enum.py
            # Login into cloudflare https://www.cloudflare.com/login
            # "Add site" to your account https://www.cloudflare.com/a/add-site
            # Provide the target domain as a site you want to add
            # Wait for cloudflare to dig through DNS data and display the results
            python cloudflare_enum.py your@email.com target.tld
            ```
            
            **Using Tools To enumerate subdomains**
            
            - assetfinder
                
                assetfinder is a passive subdomain enumeration tool from tomnomnom , it gets subdomain from different source and combine them.
                
                ```bash
                go get -u github.com/tomnomnom/assetfinder #download the assetfinder
                
                assetfinder --subs-only domain.tld # enumerates the subdomain
                ```
                
                ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2015.png)
                
                Its Fast and mostly accurate for passively collecting subdomains.
                
            - findomain
                
                findomain is mostly wellknow for its speed and accurate result , most of the time these tools like subfinder,findomain,assetfinder [ passive subdomain enumerators ] usage same process same api , the advantage of using all of them is no passively gathered subdomain gets missed.
                
                ```bash
                download from [ https://github.com/Findomain/Findomain/releases/tag/5.0.0 ]
                
                findomain -t target.tld -q 
                ```
                
                ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2016.png)
                
            - Subfinder
                
                Subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources.
                
                ```bash
                download https://github.com/projectdiscovery/subfinder/releases/tag/v2.4.8
                subfinder -d domain.tld --silent 
                ```
                
                ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2017.png)
                
            
        - Active Enumeration
            
            In this phase we are gonna enumerate subdomains actively , the online based passive subdomain database sometime miss newly added subdomain , using an active enumeration we can find active subdomains and new unique subdomains. We are gonna bruteforce for subdomain. There are many tools available for subdomain bruteforce we are gonna use selected few tools.
            
            **Nmap**
            
            There is script on nmap for bruteforcing dns , we are gonna use it to brute for subdomains.
            
            ```bash
            nmap --script dns-brute --script-args dns-brute.domain=uber.com,dns-brute.threads=6
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2018.png)
            
            ### **Goaltdns with massdns**
            
            Goaltdns is a permutation generation tool and massdns is dns reslover . We are gonna generate permutation with goaltdns and we will reslove those permutation using massdns.
            
            **Wordlists You can use :**
            
            [jhaddix/all.txt](https://www.notion.so/86a06c5dc309d08580a018c66354a056)
            
            [https://github.com/rbsec/dnscan/blob/master/subdomains-10000.txt](https://github.com/rbsec/dnscan/blob/master/subdomains-10000.txt)
            
            ```bash
            [Download-Goaltdns] https://github.com/subfinder/goaltdns
            [Download-Massdns] https://github.com/blechschmidt/massdns
            ```
            
            **Permutation generation [ goaltdns ]**
            
            We will Use two things here in Permutation , we will generate Permutation for passively gathered subdomains , and the target host.
            
            ```bash
            goaltdns -l passive-subs.txt -w all.txt -o p.sub #Permutation for passively collected domains
            goaltdns -h uber.com -w all.txt -o p2.sub # Permutation for target host
            cat p.sub p2.sub | tee -a all-sub.txt ; rm p.sub p2.sub # combine 2 results
            ```
            
            **Resolving Generated domain with massdns**
            
            After Generating permutation lets resolve those results with massdns ,  we are using this [resolver](https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt) .
            
            ```bash
            massdns -r resolvers.txt -t AAAA -w result.txt all-sub.txt
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2019.png)
            
            **If You wanna save time you can do Permutation generation and resolving on same time with suffledns.**
            
            ```bash
            [Download-suffledns] go get -v github.com/projectdiscovery/shuffledns/cmd/shuffledns
            
            shuffledns -d target.tld -list all.txt -r resolvers.txt
            ```
            
            There is Website that does bruteforce for us to find alive subdomains subdomains.
            
            [https://phpinfo.me/domain/](https://phpinfo.me/domain/)
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2020.png)
            
            **Puredns**
            
            Fast dns bruteforcer
            
            ```
            https://github.com/d3mondev/puredns [Puredns-download]
            ```
            
            ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2021.png)
            
        
        Combining Two Enumeration Technic can be usefull to get more unique subdomains . we can get passive and active domains for target at the same time.
        
        **http/https Probing**
        
        After combining all the result you need to probe all domains/subdomains to detect these are using http or https protocol, you can do that using tool called httprobe or httpx
        
        ```bash
        cat all-subs.txt | httprobe | tee subdomains.txt
        cat all-subs.txt | httpx -silent | tee subdomains.txt 
        ```
        
    - **ASN lookup**
        
        There are many ways to find asn number of a company , asn number will help us to retrieve targets internet asset .
        
        We can find asn number of a company using dig and whois , but most of the time these will give you a hosting provider asn number.
        
        example :
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2022.png)
        
        But You can find a cloud company asn with this Technic cause they host on their on server.
        
        Example : google.com
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2023.png)
        
        Now lets skip those useless talk , we can extract asn ipdata of a target company using a free api called asnlookup.com
        
        ```python
        http://asnlookup.com/api/lookup?org=tesla
        ```
        
        it will give you the result of all cidr from tesla inc.
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2024.png)
        
        Now select any of these ip and do a whois search to get asn number
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2025.png)
        
        Lets make the api cli based so we can call it from cli using python3
        
        ```python
        import requests
        import json
        def asn_lookup(company):
                headers = {
                'User-Agent': 'ASNLookup PY/Client'
                }
                asn_db=requests.get(f'http://asnlookup.com/api/lookup?org={company}',headers).text
                print(f'{Fore.GREEN}[+] {Fore.WHITE}ASN Lookup Result For {company}')
                print('')
                asndb_load=json.loads(asn_db)
                for iprange in asndb_load:
                    print(iprange)
        
        asn_lookup('company_name')
        ```
        
        so where we can use this asn number?
        
        we can use this asn number on hackers search engine like shodan to get more extracted information about the target companies internal network.
        
        Shodan Dorks:
        
        ```
        asn:AS394161
        ```
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2026.png)
        
        or we can use censys to find more information about the target company.
        
        Censys dorks:
        
        ```
        autonomous_system.asn:394161
        ```
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2027.png)
        
        or we can find asn number from whatismyip database
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2028.png)
        
- **Target Visualize/Web-Screenshot**
    
    After Enumerating subdomains/domains we need to visualize those target to see how the use interface look like , mostly is the subdomain is leaking any important information or database or not.
    
    sometime on domain/subdomain enumeration we got like 2k-10k subdomains its quite impossible to visit all of them cause it will take more than 30-40 hour , there are many tools available to screenshot those subdomains from subdomains list.
    
    **Gowitness**
    
    Its quite fast and doesn't require any external dependency.
    
    ```bash
    [download-gowitness] **https://github.com/sensepost/gowitness**
    gowitness file -f subdomains
    gowitness single https://uber.com #for single domain
    ****
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2029.png)
    
    **EyeWitness**
    
    ```bash
    [download-eyewitness] https://github.com/FortyNorthSecurity/EyeWitness
    ./EyeWitness -f subdomains.txt --web
    ```
    
    **Webscreenshot**
    
    ```bash
    [download-webscreenshot] pip3 install webscreenshot
    webscreenshot -i subdomains.txt
    
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2030.png)
    
- **Scanning for directory with possible sensitive information**
    
    sometime directory on domain or subdomain contains sensitive information like site backup , site database backup , private api interface backup or other sensitive staff stored on directory, on the sites www that disclose it to the whole internet , search engine misses those sometime cause these are less visited page . so we are gonna use some directory fuzzer / directory bruteforcer to find those sensitive files .
    
    For Wordlist you can try the seclists
    
    [SecLists/Discovery at master · danielmiessler/SecLists](https://github.com/danielmiessler/SecLists/tree/master/Discovery)
    
    **Dirsearch**
    
    dirsearch is one of the fastest and featured directory bruteforcer .
    
     
    
    ```bash
    [download-dirsearch] https://github.com/maurosoria/dirsearch
    python3 dirsearch.py -u https://target.tld -e php #single target with default wordlist
    python3 dirsearch.py -e php -u https://target.tld -w /path/to/wordlist #with wordlist
    python3 dirsearch.py -l subdomains.txt -e php # brute with list
    [-e] for extension
    [-w] for wordlist path
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2031.png)
    
    **Wfuzz**
    
    its a traditional fuzzer for web-application.its usefull when we do api testing , its usefull for fuzzing the endpoints.
    
    ```bash
    [install-wfuzz] pip3 install wfuzz / apt install wfuzz 
    wfuzz -w wordlist_path https://traget.com/FUZZ #define the brute path with FUZZ
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2032.png)
    
    You Can Read More detailed information about fuzzing on [https://book.hacktricks.xyz/pentesting-web/web-tool-wfuzz](https://book.hacktricks.xyz/pentesting-web/web-tool-wfuzz)
    
- **Parameter discovery**
    
    Web applications use parameters (or queries) to accept user input. We can test for some vulnerability on params like xss,sql,lfi,rce,etc 
    
    There are many tools available for parameter discovery .
    
    **Arjun**
    
    ```
    [download-arjun] pip3 install arjun
    arjun -i subdomains.txt -m GET -oT param.txt #for multiple target
    arjun -u target.com -m GET -oT param.txt #for single target
    
    [-m ] parameter method
    [-oT] text format output # you can see more options on arjun -h
    
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2033.png)
    
    **ParamSpider**
    
    ```
    $ git clone https://github.com/devanshbatham/ParamSpider
    $ cd ParamSpider
    $ pip3 install -r requirements.txt
    $ python3 paramspider.py --domain hackerone.com
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2034.png)
    
    or or or we can use the bruteforce method for param discovery usin parameth
    
    **parameth**
    
    ```
    [download-parameth] https://github.com/maK-/parameth
    ```
    
- **Subdomain Cname extraction**
    
    extracting cname of subdomain is usefull for us to see if any of these subdomain is pointing to other hosting/cloud services. So that  later we can test for takeover. 
    
    We can do that by using dig 
    
    ```bash
    dig CNAME 1.github.com +short
    ```
    
    so we have multiple subdomain , we can use xargs to make this automate with multitask
    
    ```bash
    cat subdomains.txt | xargs -P10 -n1 dig CNAME +short 
    ```
    
         - P10 Defines thread after that you can just tee all the cname to a text file.
    
    ```bash
    cat subdomains.txt | xargs -P10 -n1 dig CNAME +short | tee -a cnames
    ```
    
    on these cname file we are gonna filter these cnames
    
    ```
    "\.cloudfront.net"
      "\.s3-website"
      "\.s3.amazonaws.com"
      "w.amazonaws.com"
      "1.amazonaws.com"
      "2.amazonaws.com"
      "s3-external"
      "s3-accelerate.amazonaws.com"
      "\.herokuapp.com"
      "\.herokudns.com"
      "\.wordpress.com"
      "\.pantheonsite.io"
      "domains.tumblr.com"
      "\.zendesk.com"
      "\.github.io"
      "\.global.fastly.net"
      "\.helpjuice.com"
      "\.helpscoutdocs.com"
      "\.ghost.io"
      "cargocollective.com"
      "redirect.feedpress.me"
      "\.myshopify.com"
      "\.statuspage.io"
      "\.uservoice.com"
      "\.surge.sh"
      "\.bitbucket.io"
      "custom.intercom.help"
      "proxy.webflow.com"
      "landing.subscribepage.com"
      "endpoint.mykajabi.com"
      "\.teamwork.com"
      "\.thinkific.com"
      "clientaccess.tave.com"
      "wishpond.com"
      "\.aftership.com"
      "ideas.aha.io"
      "domains.tictail.com"
      "cname.mendix.net"
      "\.bcvp0rtal.com"
      "\.brightcovegallery.com"
      "\.gallery.video"
      "\.bigcartel.com"
      "\.activehosted.com"
      "\.createsend.com"
      "\.acquia-test.co"
      "\.proposify.biz"
      "simplebooklet.com"
      "\.gr8.com"
      "\.vendecommerce.com"
      "\.azurewebsites.net"
      "\.cloudapp.net"
      "\.trafficmanager.net"
      "\.blob.core.windows.net"
    ```
    
- **Crawling & Collecting Pagelinks**
    
    A url or pagelinks contains many information , there are many way to extract pagelinks from target domain.
    
    **Waybackmachine [** [https://web.archive.org/](https://web.archive.org/) **]**
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2035.png)
    
    Using Waybackmachine we could see old history of a website and pagelinks.There is a automated tools for that , the tool is written by tomnomnom.
    
    ```bash
    go get github.com/tomnomnom/waybackurls #download the script
    waybackurls target.tld
    cat domains.txt | waybackurls # for multiple domain/subdomain
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2036.png)
    
    You can use gau for collecting all the pagelinks , gau stands for gather all url.
    
    **GAU**
    
    ```
    [Download-gau] https://github.com/lc/gau
    gau target.tld
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2037.png)
    
    Gau wayback collects urls from other source , sometime these source contains outdated or dead url , dead url is useless for us.there are few tools available to crawl the life website and gather all pagelinks.
    
    **Gospider**
    
    ```bash
    [download-gospider] https://github.com/jaeles-project/gospider
    #for-single-target
    gospider -s "https://uber.com/" -o output -c 10 -d 1 --other-source --include-subs -q
    #with-list
    gospider -S sites.txt -o output -c 10 -d 1 -t 20 -q
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2038.png)
    
    ```
    You can use https://github.com/hakluke/hakrawler for the same thing.
    ```
    
- **Javascript Files Crawling & find sensitive information from jsfile**
    
    Sometime javascript files contains sensitive information like api_key,auth token or other sensitive staff . so collecting javascript file is usefull for use to get a sensitive information.
    
    There Are so many tools available for scraping javascript from page
    
    ```
    https://github.com/003random/getJS
    https://github.com/Threezh1/JSFinder
    ```
    
    **getjs**
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2039.png)
    
    I also Have written an python3 script that will help you to filter jsfiles from a webpage.
    
    [https://gist.github.com/JoyGhoshs/1131a230d7ea1a33d1d744174d49180a](https://gist.github.com/JoyGhoshs/1131a230d7ea1a33d1d744174d49180a)
    
    or You can use Waybackurls or gau to collect javascript files from target domain.
    
    ```bash
    gau target.tld | grep "\\.js" | uniq | sort -u
    waybackurls targets.tld | grep "\\.js" | uniq | sort
    ```
    
    After collecting Those javascript file we should scan those file for any sensitive information.sometime those javascript files contains endpoints these endpoints are usefull for further scanning , so lets filter those relative endpoints , there is a tool available for that.
    
     
    
    ```bash
    [download-relative-url-extractor] https://github.com/jobertabma/relative-url-extractor
    cat file.js | ./extract.rb
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2040.png)
    
    Now its time to scan for some api key from all collected js files.we can do that by using grep and regex.
    
    ```bash
    [see-the-list] https://github.com/System00-Security/API-Key-regex
    cat file.js | grep API_REGEX
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2041.png)
    
- **Domain/Subdomain Version and technology detection**
    
    Its important to scan for domain/subdomain version and technology so that we can create a model for vulnerability detection , how we are gonna approach our target site.
    
    **Wappalyzer** 
    
    Its a popular technology and version detection tool , there is chrome extension so that we can see the website we are visiting its technology.
    
    ```bash
    [install-wappalyzer] npm i -g wappalyzer
    wappalyzer https://uber.com #single domain
    cat subdomain.txt | xargs -P1 -n1 wappalyzer | tee -a result
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2042.png)
    
    **Whatweb**
    
    Its a great scanner we are using from ages , its good for its availability and its usage.
    
    ```bash
    [install-whatweb] sudo apt install whatweb
    whatweb uber.com #single domain
    cat subdomains.txt | whatweb -i | tee -a result
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2043.png)
    
    **WAD [Web application detector]**
    
    ```bash
    [install-wad] pip3 install wad
    wad -u https://uber.com #single domain
    wad -u subdomains.txt
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2044.png)
    
    **Nuclei**
    
    nuclei is a community based scanner , it scan web-applications with template , there is template on nuclei call technologies it contains detection pattern of various technologies , we can use that as a technology detection tool.
    
    ```bash
    [nuclei-download] https://github.com/projectdiscovery/nuclei
    [nuclei-technology-detection-pattern] https://github.com/projectdiscovery/nuclei-templates/tree/master/technologies
    nuclei -u https://uber.com -t -v nuclei-templates/technologies -o detect
    nuclei -l subdomain.txt -v -t nuclei-templates/technologies -o detect
    
    [! You can use -v as verbose mode so that you can see whats going on , how the sending those request]
    ```
    
    ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2045.png)
    
    most of the time we need to detect cms for mapping our attack process , there are more than 100 tools available for that some of them are online web-application based some of them are cli based.
    
    ```
    https://github.com/Tuhinshubhra/CMSeeK [CMSEEK]
    https://github.com/oways/cms-checker [CMS-CHEAKER]
    https://github.com/n4xh4ck5/CMSsc4n [CMSsc4n]
    ```
    
- **Sensitive information discovery**
    
    Sometime search engine like shodan zoomascan others contains sensitive information about the target, or the subdomains somehow those search engine disclose sensitive information about database or others.
    
    - **Google Dorking**
        
        **Google.com**
        
        We all know the well known fast and popular search engine is google.com, this search engine collects and index mostly every website available on surface web , so we can use it to find sensitive information about a domain. we will use google advance search also known as dorking.
        
        *Publicly Exposed Documents*
        
        ```bash
        site:target.tld ext:doc | ext:docx | ext:odt | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv 
        ```
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2046.png)
        
        *Directory listing* 
        
        ```
        site:target.tld intitle:index.of
        ```
        
        *Exposed Configuration file*
        
        ```
        site:target.tld ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:env
        ```
        
        *Database site exposure*
        
        ```
        site:target.tld ext:sql | ext:dbf | ext:mdb
        ```
        
        *logfile exposure*
        
        ```
        site:target.tld ext:log
        ```
        
        *backupfile exposure*
        
        ```
        site:target.tld ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup
        ```
        
        *login pages*
        
        ```
        site:target.tld inurl:login | inurl:signin | intitle:Login | intitle:"sign in" | inurl:auth
        ```
        
        *sql error on google index*
        
        ```
        site:target.tld intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"
        ```
        
        *php error on google index*
        
        ```
        site:target.tld "PHP Parse error" | "PHP Warning" | "PHP Error"
        ```
        
        *phpinfo exposure on google index*
        
        ```
        site:target.tld ext:php intitle:phpinfo "published by the PHP Group"
        ```
        
        *leakage on pastebin/pasting site*
        
        ```
        site:pastebin.com | site:paste2.org | site:pastehtml.com | site:slexy.org | site:snipplr.com | site:snipt.net | site:textsnip.com | site:bitpaste.app | site:justpaste.it | site:heypasteit.com | site:hastebin.com | site:dpaste.org | site:dpaste.com | site:codepad.org | site:jsitor.com | site:codepen.io | site:jsfiddle.net | site:dotnetfiddle.net | site:phpfiddle.org | site:ide.geeksforgeeks.org | site:repl.it | site:ideone.com | site:paste.debian.net | site:paste.org | site:paste.org.ru | site:codebeautify.org  | site:codeshare.io | site:trello.com "target.tld"
        ```
        
        *github/gitlab page from google*
        
        ```
        site:github.com | site:gitlab.com "target.tld"
        ```
        
        *search for issue on stackoverflow*
        
        ```
        site:stackoverflow.com "target.tld"
        ```
        
        List of Sensitive information Dork Just add site:"target.com" to find sensitive information about the target.
        
        [https://gist.github.com/JoyGhoshs/f8033c17e27e773c9be1ee60901a35f1](https://gist.github.com/JoyGhoshs/f8033c17e27e773c9be1ee60901a35f1)
        
         Automate full process [https://github.com/m3n0sd0n4ld/uDork](https://github.com/m3n0sd0n4ld/uDork)
        
    - **Github Recon**
        
        many of the target has github repo some of them are opensource project , sometime those github code project leaks their private api key for many services or sometime the source code disclose something sensitive thats why github is not only code vault it's also pii vault for hackers.
        
        You can do the recon 2 way on github one is manually one is automatically ,using github dorking tools.
        
        [Dork-list](https://www.notion.so/5d9b3fd4127c4564aa9d4b57e750dea2)
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2047.png)
        
        **GitDorker**
        
        ```
        [download-gitdorker] https://github.com/obheda12/GitDorker
        python3 GitDorker.py -tf TOKENSFILE -q tesla.com -d Dorks/DORKFILE -o tesla
        ```
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2048.png)
        
        Github Recon helps you to find PII more easily.
        
    - **Shodan Recon**
        
        shodan is most usefull search engine for hacker, you can find many sensitive and important information about the target from shodan , like google and github shodan also has advance search filter which will help us to find exact information about exact target.
        
        ```
        shodan.io
        [filter-refernce] https://beta.shodan.io/search/filters
        ```
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2049.png)
        
        **shodan search filter**
        
        ```
        **hostname:target.com** | to find all asset available for target.com on shodan
        **http.title:"title"** | to find server/host with similer title
        **http.html:"/file"** | to find server/host with similar path 
        **html:"context"** |  to find server/host with similar string
        **server: "apache 2.2.3"** | ****to find server/host with same server
        **port:80** | to find server/host with same port
        **os:"windows"** | to find server/host with same os
        **asn:AS3214** | to find host/server with matched asn
        **http.status:200** | to find server/host with 200 http response code
        **http.favicon.hash:"hash"** | to find server/host with same favico hash
        **ssl.cert.subject.cn:"uber.com"** | find all server/host with same common name
        **product: "service_name"** | ****to find all the server/host with same service
        ```
        
        we can use these filter to create a perfect query to search vulnerability or sensitive information on shodan.
        
        Example:
        
        ```
        hostname:uber.com html:"db_uname:" port:"80" http.status:200 # this will find us a asset of uber.com with db_uname: with it with staus response code 200
        http.html:/dana-na/ ssl.cert.subject.cn:"uber.com" # this will find us Pulse VPN with possible CVE-2019-11510
        html:"horde_login" ssl.cert.subject.cn:"uber.com"  # this will find us Horde Webamil with possible CVE 2018-19518
        We can Repet the second 2 process also with product filter Ex:
        product:"Pulse Secure" ssl.cert.subject.cn:"uber.com"
        http.html:"* The wp-config.php creation script uses this file" hostname:uber.com # this will find us open wp-config.php file with possible sensitive credential
        ```
        
        Suppose we know a active exploit for apache 2.1 , to check manually to see which of our target subdomain is using apache 2.1 will cost us time and brain , for that we can create a dork on shodan to help us in this subject , **Example : server: "apache 2.1" hostname:"[target.com](http://target.com)"** we can replace the hostname to get more accurate result for target.com using ssl.cert.subject.cn:"target.com" , this will check if the target host/server contains target.com on their ssl or not.
        
    - **Leakix Scan**
        
        leakix is most underrated search engine for leaks and misconfiguration , it can find the leak for .git .env phpinfo() and many others. you can use it directly from the browser or use its client.
        
         
        
        ```
        https://leakix.net
        ```
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2050.png)
        
        Cli Client
        
        ```
        [download] https://github.com/LeakIX/LeakIXClient
        ```
        
        or You can use my python3 based client which grubs the result directly from web
        
        [https://gist.github.com/JoyGhoshs/c20865579d347aef4180ab6a30d3d8e1](https://gist.github.com/JoyGhoshs/c20865579d347aef4180ab6a30d3d8e1)
        
        ![Untitled](Information%20Gathering%20%5B%20Reloaded%20%5D%201d11633015374f1797b56a2447ced9a4/Untitled%2051.png)