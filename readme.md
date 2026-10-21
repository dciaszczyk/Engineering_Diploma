tu jest inżynierka


1. Najpierw prosty sketch łączący się z klientem po http (na zmianę :8000/1 :8000/2) - sketch_wifi 
2. dump z wiresharka pokazujący budowę i przejrzystość pakietów - csv z http w nazwie, i pcapng
3. prototyp pokazujący warstwową budowę wiadomości - sketch_prosta_wiadomosc
4. dump z wiresharka pokazujący pakiety warstwowe - cs_prototyp i dump_prototyp -- zmieniają się o długość nagłówka (7), dalej w cleartext - widać wiadomość która jest przesyłana (hello world)
5. prototyp z szyfrowaniem na razie ze stałymi kluczami - sketch_szyfrowana_wiad
6. dump z wiresharka pokazujący że pakiety dalej zmieniają długość, ale nie wiadomo już co mają - dump_enc_prot i csv_enc_prot
