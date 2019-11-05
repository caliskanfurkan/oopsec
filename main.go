package main

import (
	"log"
	"strings"
	"encoding/csv"
	"os"
	"bufio"
	"fmt"
	"github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"
)
func main() {

	file, err := os.Open("iocs")
	if err != nil {
	    log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
	    fmt.Print(scanner.Text()+"\r\t\t\t\t")
	    domainBak(scanner.Text())
	}

	if err := scanner.Err(); err != nil {
	    log.Fatal(err)
	}
}

func domainBak(_domain string) {
	result, err := whois.Whois(_domain)
	if err == nil {
		resultik, erriki := whoisparser.Parse(result)
		if erriki == nil {
			createdate := resultik.Registrar.CreatedDate
			fmt.Print(string(createdate))

			_temizDomain := strings.TrimRight(_domain,"\n")
			 lines, err := ReadCsv("top-1m.csv")
			 if err != nil {
					panic(err)
		         }

			for _, line := range lines {
				data := CsvLine{
				    sira: line[0],
				    domain: line[1],
				}
				if _temizDomain==data.domain {
					fmt.Print(" -> [!] Top 1M'da")
				}
	                 }
			 fmt.Println()


			}
	}
}
func check(e error) {
    if e != nil {
        panic(e)
    }
}

type CsvLine struct {
    sira string
    domain string
}

func ReadCsv(filename string) ([][]string, error) {

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


