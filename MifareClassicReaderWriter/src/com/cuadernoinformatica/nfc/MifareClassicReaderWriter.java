/*
 * Copyright 2024 Alejandro Sánchez <web@cuadernoinformatica.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.cuadernoinformatica.nfc;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class MifareClassicReaderWriter {
	
	public static int CLASS = 0xFF;
	public static int GET_UID = 0xCA;
	public static int KEY_A = 0x60;
	public static int KEY_B = 0x61;
	public static int LOAD_KEY = 0x82;
	public static int READ_BLOCK = 0xB0;
	public static int WRITE_BLOCK = 0xD6;
	public static int BLOCK_BYTES = 0x10;
	public static int VALUE_BLOCK_COMMAND = 0xF0;
	public static int DECREMENT_VALUE_BLOCK = 0xC0;
	public static int INCREMENT_VALUE_BLOCK = 0xC1;
			
	protected CardTerminal terminal;
	protected Card card;
	protected CardChannel channel;
	protected String atr;
	protected String type;
	protected String typeName;
	protected int cardBlocksNumber;
	protected int cardSectorsNumber;

	public MifareClassicReaderWriter() throws MifareClassicCardException, CardException {
		
		terminal = TerminalFactory.getDefault().terminals().list().get(0);
	}
	
	public CardTerminal getTerminal() {
		return terminal;
	}
	
	public Card getCard() {
		return card;
	}
	
	public CardChannel getChannel() {
		return channel;
	}
	
	public String getATR() {
		return atr;
	}
	
	public String getType() {
		return type;
	}
	
	public String getTypeName() {
		return typeName;
	}
	
	public int getCardBlocksNumber() {
		return cardBlocksNumber;
	}
	
	public int getCardSectorsNumber() {
		return cardSectorsNumber;
	}
	
	public String encodeHexString(byte[] data) {
		return HexFormat.of().formatHex(data).toUpperCase();
	}
	
	public byte[] decodeHexString(String data) {
		return HexFormat.of().parseHex(data);
	}
	
	public byte[] concatArrays(byte[] data1, byte[] data2) {
		byte[] data3 = Arrays.copyOf(data1, data1.length + data2.length);
		System.arraycopy(data2, 0, data3, data1.length, data2.length);
		return data3;
	}
	
	public boolean isSectorTrailer(int block) {
		return block < 128 ? (block + 1) % 4 == 0 : (block + 1) % 16 == 0;
	}
	
	protected String readData(String[] args) throws IOException {
		String data;
		
		if (args.length > 4) {
			data = args[4];
		} else {
			data = new String(System.in.readAllBytes(), StandardCharsets.UTF_8)
					.replace(System.lineSeparator(), "");
		}
		
		return data;
	}
	
	protected ResponseAPDU transmit(CommandAPDU command) throws CardException, MifareClassicCardException {
		ResponseAPDU response = channel.transmit(command);
		
		int status = response.getSW();
				
		if (status != 0x9000) {
			String message;
									
			switch (status) {
			case 0x6982:
				message = "0x6982 - Security status not satisfied.";
				break;
		
			default:
				message = "0x" + Integer.toHexString(status);
			}
			
			throw new MifareClassicCardException(status, message);
		}
		
		return response;
	}
	
	public void readCard() throws CardException, MifareClassicCardException {
				
		terminal.waitForCardPresent(0);
		
		card = terminal.connect("*");
		
		atr = encodeHexString(card.getATR().getBytes());
		
		if (atr.length() < 30) {
			throw new MifareClassicCardException("Unknown Card Type.");
		}
		
		type = atr.substring(26, 30);
								
		switch (type) {
		case "0001":
			cardBlocksNumber = 64;
			cardSectorsNumber = 16;
			typeName = "Mifare Classic 1K";
			break;
		
		case "0002":
			cardBlocksNumber = 256;
			cardSectorsNumber = 40;
			typeName = "Mifare Classic 4K";
			break;
			
		default: 
			throw new MifareClassicCardException("Unsupported Card Type: " + type);
		}
		
		channel = card.getBasicChannel();
	}
		
	public String getUID() throws CardException, MifareClassicCardException {
		return encodeHexString(transmit(new CommandAPDU(CLASS, GET_UID, 0x00, 0x00, 0x100)).getData());
	}
	
	public void loadKey(int keyAB, byte[] key) throws CardException, MifareClassicCardException {
		transmit(new CommandAPDU(CLASS, LOAD_KEY, 0x00, keyAB, key));
	}
	
	public void loadKey(int keyAB, String key) throws CardException, MifareClassicCardException {
		loadKey(keyAB, decodeHexString(key));
	}
	
	public byte[] readBlock(int block) throws CardException, MifareClassicCardException {
		return readBlock(block, false);
	}
	
	protected byte[] readBlock(int block, boolean sectorTrailer) throws CardException, MifareClassicCardException {
		
		if (!sectorTrailer && isSectorTrailer(block)) {
			throw new MifareClassicCardException("Sector trailer must be read with the"
					+ " \"read-sector-trailer\" action.");
		}
		
		return transmit(new CommandAPDU(CLASS, READ_BLOCK, 0x00, block, BLOCK_BYTES)).getData();
	}
	
	public String readBlockHexString(int block) throws CardException, MifareClassicCardException {
		return encodeHexString(readBlock(block));
	}
	
	public String readBlockString(int block) throws CardException, MifareClassicCardException {
		return new String(readBlock(block), StandardCharsets.UTF_8);
	}
	
	public void writeBlock(int block, byte[] data) throws MifareClassicCardException, CardException {
		writeBlock(block, data, false);
	}
	
	protected void writeBlock(int block, byte[] data, boolean sectorTrailer) throws MifareClassicCardException, CardException {
		
		if (!sectorTrailer && isSectorTrailer(block)) {
			throw new MifareClassicCardException("Sector trailer must be written with the"
					+ " \"write-sector-trailer\" action.");
		}
		
		if (data.length != 16) {
			throw new MifareClassicCardException("Invalid Data Length: " + data.length);
		}
		
		transmit(new CommandAPDU(CLASS, WRITE_BLOCK, 0x00, block, data));
	}
	
	public void writeBlockHexString(int block, String data) throws MifareClassicCardException, CardException {
		writeBlock(block, decodeHexString(data));
	}
	
	public void writeBlockString(int block, String data) throws MifareClassicCardException, CardException {
		
		byte[] blockBytes = new byte[16];
		byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);		
		
		if (dataBytes.length > blockBytes.length) {
			throw new MifareClassicCardException("Invalid String Length: " + dataBytes.length);
		}
		
		System.arraycopy(dataBytes, 0, blockBytes, 0, dataBytes.length);
		
		writeBlock(block, blockBytes);
	}
	
	public void clearBlock(int block) throws MifareClassicCardException, CardException {
		writeBlockHexString(block, "00000000000000000000000000000000");
	}
	
	public int readValueBlock(int block) throws CardException, MifareClassicCardException {
		byte[] value = Arrays.copyOfRange(readBlock(block), 0, 4);
		return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).put(value).getInt(0);
	}
	
	public void incrementValueBlock(int block, int value) throws CardException, MifareClassicCardException {
		valueBlockCommand(INCREMENT_VALUE_BLOCK, block, value);
	}
	
	public void decrementValueBlock(int block, int value) throws CardException, MifareClassicCardException {
		valueBlockCommand(DECREMENT_VALUE_BLOCK, block, value);
	}
	
	protected void valueBlockCommand(int command, int block, int value) throws CardException, MifareClassicCardException {
		byte[] commandBytes = new byte[] {(byte) command, (byte) block};
		byte[] valueBytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
				.putInt(value).array();
					
		transmit(new CommandAPDU(CLASS, VALUE_BLOCK_COMMAND, 0x00, block,
				concatArrays(commandBytes, valueBytes)));
	}
	
	public void formatValueBlock(int block) throws MifareClassicCardException, CardException {
		writeBlockHexString(block, "00000000FFFFFFFF0000000000FF00FF");
	}
	
	public byte[] readSector(int sector) throws CardException, MifareClassicCardException {
		return readSector(new Sector(sector));
	}
	
	public byte[] readSector(Sector sector) throws CardException, MifareClassicCardException {
		int startBlock = sector.getStartBlock();
		int dataBlocksNumber = sector.getDataBlocksNumber();
		
		byte[] blocks = new byte[dataBlocksNumber * 16];
		
		for (int x = 0; x < dataBlocksNumber; x++) {
			byte[] block = readBlock(startBlock + x);
			
			System.arraycopy(block, 0, blocks, x * 16, block.length);
		}
		
		return blocks;
	}
	
	public String readSectorHexString(int sector) throws CardException, MifareClassicCardException {
		return encodeHexString(readSector(sector));
	}
	
	public String readSectorString(int sector) throws CardException, MifareClassicCardException {
		return new String(readSector(sector), StandardCharsets.UTF_8);
	}
	
	public String readSectorInfo(int sector) throws CardException, MifareClassicCardException {
		return readSectorInfo(new Sector(sector));
	}
		
	public String readSectorInfo(Sector sector) throws CardException, MifareClassicCardException {
		StringBuilder builder = new StringBuilder();
		int digits = String.valueOf(cardBlocksNumber).length(); 
		int startBlock = sector.getStartBlock();
		int blocksNumber = sector.getBlocksNumber();
					
		builder.append("Sector " + sector.getNumber() + ":\n");
		
		for (int x = 0; x < blocksNumber; x++) {
			
			builder.append(String.format("%" + digits + "d", startBlock + x) + ":");
			
			try {
				byte[] block = readBlock(startBlock + x, true);
							
				builder.append(encodeHexString(block));
					
				if (startBlock == 0 && x == 0)  {
					builder.append(" - <UID - Manufacturer Data>");
				} else if (x != blocksNumber - 1) {
					builder.append(" - " + new String(block, StandardCharsets.UTF_8)
							.replaceAll("[\\p{C}�]", " "));
				} else {
					builder.append(" - <Sector Trailer>");
				}
					
			} catch (MifareClassicCardException e) {
				builder.append("Error: " + e.getMessage());
			}
			
			builder.append("\n");
		}
		
		return builder.toString();
	}
		
	public void writeSector(int sector, byte[] data) throws MifareClassicCardException, CardException {
		writeSector(new Sector(sector), data);
	}
	
	public void writeSector(Sector sector, byte[] data) throws MifareClassicCardException, CardException {
		int startBlock = sector.getStartBlock();
		int dataBlocksNumber = sector.getDataBlocksNumber();
				
		byte[] sectorBytes = new byte[dataBlocksNumber * 16];
				
		if (data.length > sectorBytes.length) {
			throw new MifareClassicCardException("Invalid Data Length: " + data.length);
		}
						
		System.arraycopy(data, 0, sectorBytes, 0, data.length);
		
		for (int x = 0; x < dataBlocksNumber; x++) {
			
			int block = startBlock + x;
			int start = x * 16;
			int end = start + 16;
					
			writeBlock(block, Arrays.copyOfRange(sectorBytes, start, end));
		}
	}
	
	public void writeSectorHexString(int sector, String data) throws MifareClassicCardException, CardException {
		writeSector(sector, decodeHexString(data));
	}
	
	public void writeSectorString(int sector, String data) throws MifareClassicCardException, CardException {
		writeSector(sector, data.getBytes(StandardCharsets.UTF_8));
	}
	
	public void clearSector(int sector) throws MifareClassicCardException, CardException {
		clearSector(new Sector(sector));
	}
	
	public void clearSector(Sector sector) throws MifareClassicCardException, CardException {
		int startBlock = sector.getStartBlock();
		int dataBlocksNumber = sector.getDataBlocksNumber();
		
		for (int x = 0; x < dataBlocksNumber; x++) {
			clearBlock(startBlock + x);
		}
	}
	
	public String readSectorTrailer(int sector) throws CardException, MifareClassicCardException {
		return readSectorTrailer(new Sector(sector));
	}
	
	public String readSectorTrailer(Sector sector) throws CardException, MifareClassicCardException {
		return encodeHexString(readBlock(sector.getSectorTrailer(), true));
	}
	
	public void writeSectorTrailer(int sector, String data) throws MifareClassicCardException, CardException {
		writeSectorTrailer(new Sector(sector), data);
	}
	
	public void writeSectorTrailer(Sector sector, String data) throws MifareClassicCardException, CardException {
		writeBlock(sector.getSectorTrailer(), decodeHexString(data), true);
	}
	
	public String readCardInfo() throws CardException, MifareClassicCardException {
		
		StringBuilder builder = new StringBuilder();
		
		builder.append("Terminal: " + terminal + "\n");
		builder.append("Card: " + card + "\n");
		builder.append("Card ATR: " + atr + "\n");
		builder.append("Card Type: " + typeName + "\n");
		builder.append("Card UID: " + getUID() + "\n");
		builder.append("Card Data:\n");
		
		for (int sector = 0; sector < cardSectorsNumber; sector++) {
			builder.append(readSectorInfo(sector) + "\n");
		}
		
		return builder.toString();
	}
		
	public void disconnect() throws CardException {
		card.disconnect(false);
	}
	
	public static void main(String[] args) {
		try {
				
			if (args.length == 0) {
				System.out.println("Usage:"
						+ "\n\tmcrw a|b key action block|sector"
							+ " data|value"
				
						+ "\n\techo $data | mcrw a|b"
							+ " key action block|sector\n");
				
				System.out.println("Actions:"
						+ " \n\tread-block block"
						+ " \n\tread-block-string block"
						+ " \n\twrite-block block data"
						+ " \n\twrite-block-string block data"
						+ " \n\tclear-block block"
						+ " \n"
						+ " \n\tformat-value-block block"
						+ " \n\tread-value-block block"
						+ " \n\tincrement-value-block block value"
						+ " \n\tdecrement-value-block block value"
						+ " \n"
						+ " \n\tread-sector sector"
						+ " \n\tread-sector-string sector"
						+ " \n\tread-sector-info sector"
						+ " \n\twrite-sector sector data"
						+ " \n\twrite-sector-string sector data"
						+ " \n\tclear-sector sector"
						+ " \n"
						+ " \n\tread-sector-trailer sector"
						+ " \n\twrite-sector-trailer sector data"
						+ " \n"
						+ " \n\tread-card-info\n");
				
				System.out.println("Examples:"
						+ "\n\tmcrw a 08429a71b536"
							+ " write-block 4 4578616d706c6520537472696e670000"
				
						+ "\n\tmcrw b 05c4f163e7d2"
							+ " write-block-string 5 \"Example String\""
				
						+ "\n\tmcrw b 05c4f163e7d2"
							+ " increment-value-block 6 10");
				return;
			}			
					
			int keyAB = 0;
						
			switch (args[0]) {
			case "a":
				keyAB = KEY_A;
				break;
				
			case "b":
				keyAB = KEY_B;
				break;
			
			default:
				throw new MifareClassicCardException("Invalid Key: " + args[0]);
			}
						
			String key = args[1];
			
			if (key.length() != 12) {
				throw new MifareClassicCardException("Invalid Key Length: " + key.length());
			}
					
			MifareClassicReaderWriter device = new MifareClassicReaderWriter();
			device.readCard();
			device.loadKey(keyAB, key);
			
			String action = args[2];
			int block;
			int sector;
			int value;
			String data;
			
			switch (action) {
			case "read-block":
				block = Integer.parseInt(args[3]);
				System.out.println(device.readBlockHexString(block));
				break;
			
			case "read-block-string":
				block = Integer.parseInt(args[3]);
				System.out.println(device.readBlockString(block));
				break;
				
			case "write-block": 
				block = Integer.parseInt(args[3]);
				data = device.readData(args);
				device.writeBlockHexString(block, data);
				break;
				
			case "write-block-string":
				block = Integer.parseInt(args[3]);
				data = device.readData(args);
				device.writeBlockString(block, data);
				break;
				
			case "clear-block":
				block = Integer.parseInt(args[3]);
				device.clearBlock(block);
				break;
			
			case "format-value-block":
				block = Integer.parseInt(args[3]);
				device.formatValueBlock(block);
				break;
				
			case "read-value-block":
				block = Integer.parseInt(args[3]);
				System.out.println(device.readValueBlock(block));
				break;
				
			case "increment-value-block":
				block = Integer.parseInt(args[3]);
				value = Integer.parseInt(args[4]);
				device.incrementValueBlock(block, value);
				break;
				
			case "decrement-value-block":
				block = Integer.parseInt(args[3]);
				value = Integer.parseInt(args[4]);
				device.decrementValueBlock(block, value);
				break;
			
			case "read-sector":
				sector = Integer.parseInt(args[3]);
				System.out.println(device.readSectorHexString(sector));
				break;
				
			case "read-sector-string":
				sector = Integer.parseInt(args[3]);
				System.out.println(device.readSectorString(sector));
				break;
			
			case "read-sector-info":
				sector = Integer.parseInt(args[3]);
				System.out.print(device.readSectorInfo(sector));
				break;
			
			case "write-sector":
				sector = Integer.parseInt(args[3]);
				data = device.readData(args);
				device.writeSectorHexString(sector, data);
				break;
				
			case "write-sector-string":
				sector = Integer.parseInt(args[3]);
				data = device.readData(args);
				device.writeSectorString(sector, data);
				break;
				
			case "clear-sector":
				sector = Integer.parseInt(args[3]);
				device.clearSector(sector);
				break;
			
			case "read-sector-trailer":
				sector = Integer.parseInt(args[3]);
				System.out.println(device.readSectorTrailer(sector));
				break;
				
			case "write-sector-trailer":
				sector = Integer.parseInt(args[3]);
				data = device.readData(args);
				device.writeSectorTrailer(sector, data);
				break;
			
			case "read-card-info":
				System.out.print(device.readCardInfo());
				break;
			
			default:
				throw new MifareClassicCardException("Invalid Action: " + action);
			}
			
			device.disconnect();	
			   
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
		}
	}
	
	public class Sector {
		protected int number;
		protected int startBlock;
		protected int blocksNumber;
		
		public Sector(int number) {
			this.number = number;
			
			if (number < 32) {
				startBlock = number * 4;
				blocksNumber = 4;
			} else {
				startBlock = 128 + (number - 32) * 16; 
				blocksNumber = 16;
			}
		}
		
		public int getNumber() {
			return number;
		}
		
		public int getStartBlock() {
			return startBlock;
		}
		
		public int getBlocksNumber() {
			return blocksNumber;
		}
		
		public int getDataBlocksNumber() {
			return blocksNumber - 1;
		}
		
		public int getSectorTrailer() {
			return startBlock + blocksNumber - 1;
		}
	}
}