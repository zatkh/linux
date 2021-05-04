cmd_arch/arm/boot/dts/vexpress-v2p-ca5s.dtb := mkdir -p arch/arm/boot/dts/ ; /usr/bin/ccache /home/zt/optee/build/../toolchains/aarch32/bin/arm-linux-gnueabihf-gcc -E -Wp,-MD,arch/arm/boot/dts/.vexpress-v2p-ca5s.dtb.d.pre.tmp -nostdinc -I./scripts/dtc/include-prefixes -undef -D__DTS__ -x assembler-with-cpp -o arch/arm/boot/dts/.vexpress-v2p-ca5s.dtb.dts.tmp arch/arm/boot/dts/vexpress-v2p-ca5s.dts ; ./scripts/dtc/dtc -O dtb -o arch/arm/boot/dts/vexpress-v2p-ca5s.dtb -b 0 -iarch/arm/boot/dts/ -i./scripts/dtc/include-prefixes -Wno-unit_address_vs_reg -Wno-unit_address_format -Wno-gpios_property -Wno-avoid_unnecessary_addr_size -Wno-alias_paths -Wno-graph_child_address -Wno-graph_port -Wno-unique_unit_address -Wno-pci_device_reg  -d arch/arm/boot/dts/.vexpress-v2p-ca5s.dtb.d.dtc.tmp arch/arm/boot/dts/.vexpress-v2p-ca5s.dtb.dts.tmp ; cat arch/arm/boot/dts/.vexpress-v2p-ca5s.dtb.d.pre.tmp arch/arm/boot/dts/.vexpress-v2p-ca5s.dtb.d.dtc.tmp > arch/arm/boot/dts/.vexpress-v2p-ca5s.dtb.d

source_arch/arm/boot/dts/vexpress-v2p-ca5s.dtb := arch/arm/boot/dts/vexpress-v2p-ca5s.dts

deps_arch/arm/boot/dts/vexpress-v2p-ca5s.dtb := \
  arch/arm/boot/dts/vexpress-v2m-rs1.dtsi \

arch/arm/boot/dts/vexpress-v2p-ca5s.dtb: $(deps_arch/arm/boot/dts/vexpress-v2p-ca5s.dtb)

$(deps_arch/arm/boot/dts/vexpress-v2p-ca5s.dtb):
