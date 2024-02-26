# Mifare Classic Reader Writer

<p>Mifare Classic card reader and writer. It can be used as a command line program or as a Java class for programming other programs.</p>

<p>Only tested with the SCL3711 reader, for other readers it may be necessary to create a subclass and rewrite the getUID, loadKey, readBlock, writeBlock and valueBlockCommand methods to modify the APDU commands.</p>

<h2>Command Line Program</h2>

<pre># mcrw

Usage:
	mcrw a|b key action block|sector data|value
	echo $data | mcrw a|b key action block|sector

Actions: 
	read-block block 
	read-block-string block 
	write-block block data 
	write-block-string block data 
	clear-block block 
 
	format-value-block block 
	read-value-block block 
	increment-value-block block value 
	decrement-value-block block value 
 
	read-sector sector 
	read-sector-string sector 
	read-sector-info sector 
	write-sector sector data 
	write-sector-string sector data 
	clear-sector sector 
 
	read-sector-trailer sector 
	write-sector-trailer sector data 
 
	read-card-info

Examples:
	mcrw a 08429a71b536 write-block 4 4578616d706c6520537472696e670000
	mcrw b 05c4f163e7d2 write-block-string 5 "Example String"
	mcrw b 05c4f163e7d2 increment-value-block 6 10</pre>

<h2>Java Class</h2>

<pre>MifareClassicReaderWriter device = new MifareClassicReaderWriter();
device.readCard();
device.loadKey(KEY_A, "ffffffffffff");
String block = device.readBlockHexString(4);</pre>

More info in <a href="https://www.cuadernoinformatica.com/2024/02/tarjetas-nfc-mifare-classic.html">"Grabación de Archivos en Casetes"</a> blog article.
