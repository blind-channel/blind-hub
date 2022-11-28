YOSYS_LIB = ./deps/yosys/asic_cell_yosys_extended.lib
YOSYS_SCRIPT = ./deps/yosys/script.abc
V2B = ./deps/v2b.py
SHA256_DIR = ./src/sha256
AES256_DIR = ./src/aes256
ZKCIRC_DIR = ./src/zero-knowledge
OUTPUT_DIR = ./output

.PHONY: build build-outdir build-sha256 build-aes256 build-zk-split-final build-zk-split-delivery build-zk-aed-txout build-zk-all clean

build: build-sha256 build-aes256 build-zk-split-final build-zk-split-delivery build-zk-aed-txout build-zk-all build-zk-sat-all

build-outdir:
	mkdir -p $(OUTPUT_DIR)

build-sha256: $(OUTPUT_DIR)/sha256.pp.bristol

$(OUTPUT_DIR)/sha256.pp.bristol: build-outdir $(SHA256_DIR)/raw_sha256.v $(SHA256_DIR)/sha256.v
	echo "# Circuit Post Processing" > yosys_script ;
	echo "read_verilog $(SHA256_DIR)/sha256.v" >> yosys_script ;
	echo "read_verilog $(SHA256_DIR)/raw_sha256.v" >> yosys_script ;
	echo "hierarchy -check -top sha256" >> yosys_script ;
	echo "flatten;" >> yosys_script ;
	echo "techmap; " >> yosys_script ;
	# echo "dfflibmap -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "abc -liberty $(YOSYS_LIB) -script $(YOSYS_SCRIPT)" >> yosys_script ;
	echo "opt_clean -purge" >> yosys_script ;
	echo "tee -a $(OUTPUT_DIR)/sha256.pp.stats stat -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "write_verilog -noattr -noexpr $(OUTPUT_DIR)/sha256.pp.v" >> yosys_script ;
	time yosys -s yosys_script ;
	# python3 $(SHA256_DIR)/remove_assign.py;
	python3 $(V2B) -v $(OUTPUT_DIR)/sha256.pp.v $(OUTPUT_DIR)/sha256.pp.bristol ;
	rm -f yosys_script

build-aes256: $(OUTPUT_DIR)/aes256.pp.bristol

$(OUTPUT_DIR)/aes256.pp.bristol: build-outdir $(AES256_DIR)/raw_aes256.v $(AES256_DIR)/aes256.v
	echo "# Circuit Post Processing" > yosys_script ;
	echo "read_verilog $(AES256_DIR)/aes256.v" >> yosys_script ;
	echo "read_verilog $(AES256_DIR)/raw_aes256.v" >> yosys_script ;
	echo "hierarchy -check -top aes256" >> yosys_script ;
	echo "flatten;" >> yosys_script ;
	echo "techmap; " >> yosys_script ;
	# echo "dfflibmap -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "abc -liberty $(YOSYS_LIB) -script $(YOSYS_SCRIPT)" >> yosys_script ;
	echo "opt_clean -purge" >> yosys_script ;
	echo "tee -a $(OUTPUT_DIR)/aes256.pp.stats stat -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "write_verilog -noattr -noexpr $(OUTPUT_DIR)/aes256.pp.v" >> yosys_script ;
	time yosys -s yosys_script ;
	# python3 $(AES256_DIR)/remove_assign.py;
	python3 $(V2B) -v $(OUTPUT_DIR)/aes256.pp.v $(OUTPUT_DIR)/aes256.pp.bristol ;
	rm -f yosys_script

build-zk-split-final: $(OUTPUT_DIR)/zk_split_final.pp.bristol

$(OUTPUT_DIR)/zk_split_final.pp.bristol: build-outdir $(AES256_DIR)/raw_aes256.v $(AES256_DIR)/aes256.v $(ZKCIRC_DIR)/zk_split_final.v
	echo "# Circuit Post Processing" > yosys_script ;
	echo "read_verilog $(ZKCIRC_DIR)/zk_split_final.v" >> yosys_script ;
	echo "read_verilog $(SHA256_DIR)/sha256.v" >> yosys_script ;
	echo "read_verilog $(SHA256_DIR)/raw_sha256.v" >> yosys_script ;
	echo "hierarchy -check -top test_zk_split_final" >> yosys_script ;
	# echo "proc; opt; fsm; opt; flatten; opt -full;" >> yosys_script ;
	# echo "techmap; opt;" >> yosys_script ;
	echo "proc; flatten; techmap; opt; " >> yosys_script;
	echo "dfflibmap -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "abc -liberty $(YOSYS_LIB) -script $(YOSYS_SCRIPT)" >> yosys_script ;
	echo "opt -full; clean;" >> yosys_script ;
	echo "opt_clean -purge" >> yosys_script ;
	echo "tee -a $(OUTPUT_DIR)/zk_split_final.pp.stats stat -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "write_verilog -noattr -noexpr $(OUTPUT_DIR)/zk_split_final.pp.v" >> yosys_script ;
	time yosys -s yosys_script ;
	python3 $(V2B) -v $(OUTPUT_DIR)/zk_split_final.pp.v $(OUTPUT_DIR)/zk_split_final.pp.bristol ;
	rm -f yosys_script

build-zk-split-delivery: $(OUTPUT_DIR)/zk_split_delivery.pp.bristol

$(OUTPUT_DIR)/zk_split_delivery.pp.bristol: build-outdir $(AES256_DIR)/raw_aes256.v $(AES256_DIR)/aes256.v $(ZKCIRC_DIR)/zk_split_delivery.v
	echo "# Circuit Post Processing" > yosys_script ;
	echo "read_verilog $(ZKCIRC_DIR)/zk_split_delivery.v" >> yosys_script ;
	echo "read_verilog $(SHA256_DIR)/sha256.v" >> yosys_script ;
	echo "read_verilog $(SHA256_DIR)/raw_sha256.v" >> yosys_script ;
	echo "hierarchy -check -top test_zk_split_delivery" >> yosys_script ;
	# echo "proc; opt; fsm; opt; flatten; opt -full;" >> yosys_script ;
	# echo "techmap; opt;" >> yosys_script ;
	echo "proc; flatten; techmap; opt; " >> yosys_script;
	echo "dfflibmap -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "abc -liberty $(YOSYS_LIB) -script $(YOSYS_SCRIPT)" >> yosys_script ;
	echo "opt -full; clean;" >> yosys_script ;
	echo "opt_clean -purge" >> yosys_script ;
	echo "tee -a $(OUTPUT_DIR)/zk_split_delivery.pp.stats stat -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "write_verilog -noattr -noexpr $(OUTPUT_DIR)/zk_split_delivery.pp.v" >> yosys_script ;
	time yosys -s yosys_script ;
	python3 $(V2B) -v $(OUTPUT_DIR)/zk_split_delivery.pp.v $(OUTPUT_DIR)/zk_split_delivery.pp.bristol ;
	rm -f yosys_script

# build-txid:  build-outdir $(AES256_DIR)/raw_aes256.v $(AES256_DIR)/aes256.v $(ZKCIRC_DIR)/zk_split_delivery.v
# 	echo "# Circuit Post Processing" > yosys_script ;
# 	echo "read_verilog $(ZKCIRC_DIR)/zk_split_delivery.v" >> yosys_script ;
# 	echo "read_verilog $(SHA256_DIR)/sha256.v" >> yosys_script ;
# 	echo "read_verilog $(SHA256_DIR)/raw_sha256.v" >> yosys_script ;
# 	echo "hierarchy -check -top txid_split_test" >> yosys_script ;
# 	echo "proc; opt; fsm; opt; flatten; opt -full;" >> yosys_script ;
# 	echo "techmap; opt;" >> yosys_script ;
# 	echo "dfflibmap -liberty $(YOSYS_LIB)" >> yosys_script ;
# 	echo "abc -liberty $(YOSYS_LIB) -script $(YOSYS_SCRIPT)" >> yosys_script ;
# 	echo "opt -full; clean;" >> yosys_script ;
# 	echo "opt_clean -purge" >> yosys_script ;
# 	echo "tee -a $(OUTPUT_DIR)/txid_split.pp.stats stat -liberty $(YOSYS_LIB)" >> yosys_script ;
# 	echo "write_verilog -noattr -noexpr $(OUTPUT_DIR)/txid_split.pp.v" >> yosys_script ;
# 	time yosys -s yosys_script ;
# 	python3 $(V2B) -v $(OUTPUT_DIR)/txid_split.pp.v $(OUTPUT_DIR)/txid_split.pp.bristol ;
# 	rm -f yosys_script

build-zk-aed-txout: $(OUTPUT_DIR)/zk_aed_timeout.pp.bristol

$(OUTPUT_DIR)/zk_aed_timeout.pp.bristol: build-outdir $(AES256_DIR)/raw_aes256.v $(AES256_DIR)/aes256.v $(ZKCIRC_DIR)/zk_aed_timeout.v
	echo "# Circuit Post Processing" > yosys_script ;
	echo "read_verilog $(ZKCIRC_DIR)/zk_aed_timeout.v" >> yosys_script ;
	echo "read_verilog $(SHA256_DIR)/sha256.v" >> yosys_script ;
	echo "read_verilog $(SHA256_DIR)/raw_sha256.v" >> yosys_script ;
	echo "hierarchy -check -top test_sighash_aed_timeout" >> yosys_script ;
	echo "proc; flatten; techmap; opt; " >> yosys_script;
	echo "dfflibmap -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "abc -liberty $(YOSYS_LIB) -script $(YOSYS_SCRIPT)" >> yosys_script ;
	echo "opt -full; clean;" >> yosys_script ;
	echo "opt_clean -purge" >> yosys_script ;
	echo "tee -a $(OUTPUT_DIR)/zk_aed_timeout.pp.stats stat -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "write_verilog -noattr -noexpr $(OUTPUT_DIR)/zk_aed_timeout.pp.v" >> yosys_script ;
	time yosys -s yosys_script ;
	python3 $(V2B) -v $(OUTPUT_DIR)/zk_aed_timeout.pp.v $(OUTPUT_DIR)/zk_aed_timeout.pp.bristol ;
	rm -f yosys_script

build-zk-all: $(OUTPUT_DIR)/zk_all.pp.bristol

$(OUTPUT_DIR)/zk_all.pp.bristol: build-outdir $(AES256_DIR)/raw_aes256.v $(AES256_DIR)/aes256.v $(ZKCIRC_DIR)/zk_split_delivery.v $(ZKCIRC_DIR)/zk_aed_timeout.v $(ZKCIRC_DIR)/zk_all.v ./src/util.v
	echo "# Circuit Post Processing" > yosys_script ;
	echo "read_verilog $(ZKCIRC_DIR)/zk_all.v" >> yosys_script ;
	echo "read_verilog $(ZKCIRC_DIR)/zk_aed_timeout.v" >> yosys_script ;
	echo "read_verilog $(ZKCIRC_DIR)/zk_split_delivery.v" >> yosys_script ;
	echo "read_verilog ./src/util.v" >> yosys_script ;
	echo "read_verilog $(SHA256_DIR)/sha256.v" >> yosys_script ;
	echo "read_verilog $(SHA256_DIR)/raw_sha256.v" >> yosys_script ;
	echo "hierarchy -check -top zk_all" >> yosys_script ;
	echo "proc; flatten; techmap; opt; " >> yosys_script;
	echo "dfflibmap -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "abc -liberty $(YOSYS_LIB) -script $(YOSYS_SCRIPT)" >> yosys_script ;
	echo "opt -full; clean;" >> yosys_script ;
	echo "opt_clean -purge" >> yosys_script ;
	echo "tee -a $(OUTPUT_DIR)/zk_all.pp.stats stat -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "write_verilog -noattr -noexpr $(OUTPUT_DIR)/zk_all.pp.v" >> yosys_script ;
	time yosys -s yosys_script ;
	python3 $(V2B) -v $(OUTPUT_DIR)/zk_all.pp.v $(OUTPUT_DIR)/zk_all.pp.bristol ;
	rm -f yosys_script

build-zk-sat-all: $(OUTPUT_DIR)/zk_sat_all.pp.bristol

$(OUTPUT_DIR)/zk_sat_all.pp.bristol: build-outdir $(AES256_DIR)/raw_aes256.v $(AES256_DIR)/aes256.v $(ZKCIRC_DIR)/zk_split_delivery.v $(ZKCIRC_DIR)/zk_aed_timeout.v $(ZKCIRC_DIR)/zk_all.v ./src/util.v
	echo "# Circuit Post Processing" > yosys_script ;
	echo "read_verilog $(ZKCIRC_DIR)/zk_all.v" >> yosys_script ;
	echo "read_verilog $(ZKCIRC_DIR)/zk_aed_timeout.v" >> yosys_script ;
	echo "read_verilog $(ZKCIRC_DIR)/zk_split_delivery.v" >> yosys_script ;
	echo "read_verilog ./src/util.v" >> yosys_script ;
	echo "read_verilog $(SHA256_DIR)/sha256.v" >> yosys_script ;
	echo "read_verilog $(SHA256_DIR)/raw_sha256.v" >> yosys_script ;
	echo "hierarchy -check -top zk_sat_all" >> yosys_script ;
	echo "proc; flatten; techmap; opt; " >> yosys_script;
	echo "dfflibmap -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "abc -liberty $(YOSYS_LIB) -script $(YOSYS_SCRIPT)" >> yosys_script ;
	echo "opt -full; clean;" >> yosys_script ;
	echo "opt_clean -purge" >> yosys_script ;
	echo "tee -a $(OUTPUT_DIR)/zk_sat_all.pp.stats stat -liberty $(YOSYS_LIB)" >> yosys_script ;
	echo "write_verilog -noattr -noexpr $(OUTPUT_DIR)/zk_sat_all.pp.v" >> yosys_script ;
	time yosys -s yosys_script ;
	python3 $(V2B) -v $(OUTPUT_DIR)/zk_sat_all.pp.v $(OUTPUT_DIR)/zk_sat_all.pp.bristol ;
	rm -f yosys_script

clean:
	rm -f yosys_script
	rm -rf $(OUTPUT_DIR)