package main

import (
	"net/http"
//	"net/url"
	"html/template"
	"log"
	"github.com/jpillora/go-tld"
	"strings"
	"encoding/csv"
	"os"
	"net"
	"fmt"
	"regexp"
	"github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"
	"github.com/gorilla/mux"
  //      "github.com/davecgh/go-spew/spew"
)

func main() {

	r := mux.NewRouter()

	r.HandleFunc("/", postHandler)

	http.ListenAndServe(":8080", r)
}


func postHandler(w http.ResponseWriter, r *http.Request) {

    if r.Method == "GET" {
        t, _ := template.ParseFiles("ioccheck.gtpl")
        t.Execute(w, nil)
    } else {
        r.ParseForm()
        ekranaYaz(r.Form["iocs"], w)
    }
}

func ekranaYaz(iocler []string, w http.ResponseWriter) {

	htmlOlus:="<html><body>"

	tnp:=strings.Split(iocler[0],"\r\n")

	for _, sit := range tnp {

	    _ioc := temizle(strings.ToLower(sit))

	    if (_ioc=="") {continue}

	    htmlOlus += "[!]  "+ _ioc + "    "

	    htmlOlus += checkIOCType(_ioc)+"       "

	    if (checkIOCType(_ioc)=="domain") {
			if domainTop1Mmi(_ioc)  {
				htmlOlus += "   Top 1M'de    "
			}
			result, _ := whois.Whois(_ioc)
			resultik, _ := whoisparser.Parse(result)
			createdate := resultik.Registrar.CreatedDate
			htmlOlus+=string(createdate)+"  "

	    }

	    if checkIOCType(temizle(_ioc)) == "ip" {

		deger, _ := privateIP(_ioc)

		if deger {
			htmlOlus+="\t****---PrivateIP---****"
	         }
	    }

	    htmlOlus+="<br>"
	}

htmlOlus+="</body></html>"

w.Header().Set("Content-Type", "text/html")
w.Write([]byte(htmlOlus))

}


func temizle(_domain string) string {
	_domainL  := strings.ToLower(_domain)
	bir	  := strings.Replace(_domainL, "[.]",".",-1)
	iki	  := strings.Replace(bir,"hxxp","http",-1)
	son	  := extractDomainFromURL(iki)

	return son
}


func privateIP(ip string) (bool, error) {
    var err error
    private := false
    IP := net.ParseIP(ip)
    if IP == nil {
        log.Fatal(err)
    } else {
        _, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
        _, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
        _, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
        private = private24BitBlock.Contains(IP) || private20BitBlock.Contains(IP) || private16BitBlock.Contains(IP)
    }
    return private, err
}


func domainTop1Mmi(_domain string) bool {
			_temizDomain := strings.TrimRight(_domain,"\n")
			 lines, err := readCsv("top-1m.csv")
			 if err != nil {
					panic(err)
		         }
			 for _, line := range lines {
				data := csvLine{
				    sira: line[0],
				    domain: line[1],
				}
				if _temizDomain == data.domain {
					return true
				}
	                 }
			 fmt.Print()
	return false
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}

type csvLine struct {
    sira string
    domain string
}

func readCsv(filename string) ([][]string, error) {

    f, err := os.Open(filename)
    if err != nil {
        return [][]string{}, err
    }
    defer f.Close()

    lines, err := csv.NewReader(f).ReadAll()
    if err != nil {
        return [][]string{}, err
    }

    return lines, nil
}

func checkIOCType(line string) string {
	reIP := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
        reDomain := regexp.MustCompile(`^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z
 ]{2,3})$`)

	if reDomain.MatchString(line) {
		return "domain"
	} else if reIP.MatchString(line) {
		return "ip"
	} else {
		return "hash"
	}
}

func extractDomainFromURL(gelenURL string) string {
	if strings.Contains(gelenURL,"/") {
		u,_ := tld.Parse(gelenURL)
			if u.Subdomain == "" {
				return u.Domain+"."+u.TLD
			}
			return u.Subdomain + "." + u.Domain + "." + u.TLD
	}
	return gelenURL

}
