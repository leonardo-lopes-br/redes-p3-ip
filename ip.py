from iputils import *


class IP:
    def _init_(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.contador = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, timeToLive, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        novoTimeToLive = timeToLive - 1
        if novoTimeToLive == 0:
            #Criando ICMP
            datagramaICMP = self.criarICMP(datagrama)
            # Enviando resposta ICMP time exceeded
            self.enviar(datagramaICMP, src_addr, 0x01)
            return
        
        datagrama = self.mudar_timeToLive(datagrama, novoTimeToLive)

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.

        # Convertendo dest_addr para um endereço IP 
        dest_addr = str2addr(dest_addr)  
        dest_addr, = struct.unpack('!I', dest_addr)

        proxSaltos = []
        # Iterando sobre a tabela para guardar os próximos saltos na lista proxSaltos
        for entrada in self.tabela_encaminhamento:
            cidr, prox_salto = entrada
            endereco, n = cidr.split("/")

            endereco = str2addr(endereco)
            endereco, = struct.unpack('!I', endereco)
            endereco_destino = dest_addr >> 32 - int(n)
            endereco_destino = endereco_destino << 32 - int(n)    
            if endereco == endereco_destino:
                proxSaltos.append((int(n), prox_salto))
        # selecionando a entrada com o prefixo mais longo em caso de empate.
        if len(proxSaltos):
            proxSalto_ordenados = sorted(proxSaltos, reverse=True, key=lambda tup: tup[0])
            maior_prefixo = proxSalto_ordenados[0]
            prox_salto_resultado = maior_prefixo[1]
            # Retorna o próximo salto
            return prox_salto_resultado

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela_encaminhamento = tabela 

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr, protocol=0x06):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        # Obtendo o endereço IP de origem e destino
        ipOrigem, = struct.unpack('!I', str2addr(self.meu_endereco))
        ipDestino, = struct.unpack('!I', str2addr(dest_addr))

        # Montando o cabeçalho IPv4

        # Versão IPv4 e tamanho do cabeçalho 
        ver_tam_cabecalho = struct.pack("!B", 0x45)
        # Tipo de serviço 
        tipoServico = struct.pack("!B", 0x00)  
        # Tamanho total do datagrama 
        tamanho = struct.pack("!H", 20 + len(segmento))  
        # ID do datagrama
        id_datagrama = struct.pack("!H", self.contador)
        # Flags e offset 
        flags_e_offset = struct.pack("!H", 0x0000)  
        # Tempo de vida 
        timeToLive = struct.pack("!B", 64)  
        # Protocolo 
        byte_protocolo = struct.pack("!B", protocol)
        # Campo de checksum 
        checksum = struct.pack("!H", 0x0000)  

        # Montando o cabeçalho IP 
        header = [ver_tam_cabecalho, tipoServico, tamanho, id_datagrama, flags_e_offset, timeToLive, byte_protocolo, 
                  checksum, struct.pack("!I", ipOrigem), struct.pack("!I", ipDestino)]

        # Calculando o checksum do cabeçalho IP
        header_checksum = calc_checksum(b"".join(header))
        header_checksum = struct.pack("!H", header_checksum)

        # Remontando o cabeçalho IP com o checksum correto
        datagrama = ver_tam_cabecalho + tipoServico + tamanho + id_datagrama + flags_e_offset + timeToLive + byte_protocolo + header_checksum \
        + struct.pack("!I", ipOrigem) + struct.pack("!I", ipDestino)

        # Enviando o datagrama + segmento para o next hop
        self.enlace.enviar(datagrama + segmento, self._next_hop(dest_addr))
        # Incrementando o contador para o próximo datagrama
        self.contador += 1
    
    def criarICMP(self, datagrama):
        # Montando o cabeçalho ICMP

        # Type 11 (Time Exceeded), Code 0
        type_and_code = struct.pack("!BB", 0x0b, 0x00)
        # Campo checksum inicializado como 0
        checksum = struct.pack("!H", 0)
        # Campos não utilizados (0)
        unused = struct.pack("!I", 0)  
        # Copiar os primeiros 28 bytes do datagrama original
        resto = datagrama[:28]  

        # Montando o payload do ICMP 
        payloadICMP = type_and_code + checksum + unused + resto

        # Calculando o checksum do payload do ICMP
        checksum = calc_checksum(payloadICMP)
        checksum = struct.pack("!H", checksum)

        # Remontando o payload do ICMP com o checksum certo
        payloadICMP = type_and_code + checksum + unused + resto
        return payloadICMP

    def mudar_timeToLive(self, datagrama, novo_ttl):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        ver_tam_cabecalho = struct.pack("!B", 0x45)

        dscp_ecn = struct.pack("!B", dscp & ecn)

        tamanho = struct.pack("!H", len(payload))

        id_bytes = struct.pack("!H", identification)

        flags_e_offset = struct.pack("!H", flags & frag_offset)

        new_TimeToLive = struct.pack("!B", novo_ttl)

        protocolo = struct.pack("!B", proto)

        checksum = struct.pack("!H", 0x0000)

        ipOrigem, = struct.unpack('!I', str2addr(src_addr))
        ipOrigem = struct.pack("!I", ipOrigem)

        ipDestino, = struct.unpack('!I', str2addr(dst_addr))
        ipDestino = struct.pack("!I", ipDestino)

        #Montando o datagrama e verificando o checksum do datagrama
        datagrama = ver_tam_cabecalho + dscp_ecn + tamanho + id_bytes + flags_e_offset \
        + new_TimeToLive + protocolo + checksum + ipOrigem + ipDestino
        headerChecksum = calc_checksum(datagrama)
        checksum = struct.pack("!H", headerChecksum)
        datagrama = ver_tam_cabecalho + dscp_ecn + tamanho + id_bytes + flags_e_offset \
        + new_TimeToLive + protocolo + checksum + ipOrigem + ipDestino
        #Retornando datagrama
        return datagrama