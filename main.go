package main

import (
	"log"
	"fmt"
	"encoding/csv"
	"os"
	"bufio"
	"github.com/likexian/whois-go"
	"github.com/likexian/whois-parser-go"
)

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

func main() {

	file, err := os.Open("iocs")
	if err != nil {
	    log.Fatal(err)
	}
	defer file.Close()
	
	lines, err := ReadCsv("top-1m.csv")
	if err != nil {
		panic(err)
	}

	for _, line := range lines {
		data := CsvLine{
		    sira: line[0],
		    domain: line[1],
		}
		fmt.Println(data.sira + " " + data.domain)
	    }


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
			log.Println(string(createdate))
		}
	}
}
