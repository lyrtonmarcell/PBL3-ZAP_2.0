# ZapsZap Release Candidate

# 1. Introdução.

No cenário atual, onde a comunicação instantânea é essencial para a eficiência e colaboração nas empresas, a relevância dos aplicativos de mensagens é inquestionável. Estes aplicativos não apenas facilitam a troca de informações, mas também redefinem os padrões de comunicação, proporcionando recursos avançados como chamadas de vídeo, compartilhamento de arquivos e integração com diversas plataformas. A segurança, através da criptografia de ponta a ponta, é um componente crucial para proteger a privacidade das comunicações.

Neste contexto, uma startup contratou a equipe de desenvolvimento para criar um software de mensagens instantâneas focado no ambiente corporativo, baseado no modelo peer-to-peer (P2P). O desafio é implementar uma solução descentralizada, sem a dependência de um servidor central, permitindo a troca segura de mensagens de texto entre grupos de usuários dentro de uma empresa.

O protótipo deve operar utilizando sockets UDP, considerando o modelo de falhas da Internet, onde tanto mensagens quanto processos podem sofrer falhas de omissão. O serviço deve oferecer confiabilidade, garantindo que uma mensagem seja recebida apenas uma vez e exibida na mesma ordem em todas as interfaces dos usuários. Além disso, mensagens não visualizadas durante a desconexão do usuário devem ser apresentadas quando ele se reconectar ao sistema.

# 2. Fundamentação Teórica

Para a construção desse sistema conceitos deveriam ser bem consolidados, tornando-os base para esse trabalho.

# 2.1 Modelo Peer-to-Peer (P2P):

As redes P2P surgiram em 1999, inicialmente associadas a controvérsias, como o caso do Napster, mas evoluíram para desempenhar papéis valiosos e legais. Essas redes são formadas por computadores domésticos, chamados peers. A característica fundamental é a capacidade de compartilhar recursos, onde cada computador atua alternadamente como cliente, buscando conteúdo, e como servidor, fornecendo conteúdo para outros peers. O grande atrativo das redes P2P é a ausência de uma infraestrutura centralizada, permitindo que qualquer pessoa contribua para a distribuição de conteúdo. A figura 1 apresenta a esquematização do modelo Peer-to-peer.

![Figura 1: Arquitetura do modelo P2P](https://www.gta.ufrj.br/ensino/eel878/redes1-2016-1/16_1/p2p/images/funcionamento.png)

<p align="center">
  <em>https://www.gta.ufrj.br/ensino/eel878/redes1-2016-1/16_1/p2p/images/funcionamento.png</em><br>
  <em>Figura 1: Arquitetura do modelo P2P</em>
</p>
O protocolo P2P mais proeminente hoje é o BitTorrent, amplamente utilizado para compartilhar vídeos licenciados e de domínio público, além de outros conteúdos volumosos. Ao contrário das CDNs, que exigem uma grande empresa para operação, as redes P2P capacitam qualquer indivíduo com um computador a participar ativamente na distribuição de conteúdo, proporcionando uma notável capacidade de competir com os maiores sites da web. Esse aspecto descentralizado e democratizado das redes P2P é o que as torna atrativas, permitindo que até mesmo indivíduos e pequenas comunidades exerçam influência significativa na distribuição de conteúdo online.

# 2.2 Sockets UDP:

O UDP é um protocolo de transporte não orientado a conexões, integrante do conjunto de protocolos da Internet. Diferentemente do TCP, que oferece uma comunicação confiável e orientada a conexões, o UDP é projetado para simplicidade e eficiência em aplicações que não requerem garantia de entrega.

Principais Características do UDP:

1. Simplicidade:

O UDP é um protocolo simples, oferecendo uma camada básica para envio de datagramas IP encapsulados.

2. Ausência de Conexão:

Não é necessário estabelecer uma conexão antes da transmissão de dados. Isso o torna ideal para aplicações que necessitam de baixa sobrecarga de comunicação.

3. Demultiplexação via Portas:

Utiliza portas para identificar pontos extremos nas máquinas de origem e destino, permitindo a demultiplexação de dados para os processos corretos.

4. Cabeçalho Simples:

O cabeçalho UDP consiste em 8 bytes, contendo informações como portas de origem e destino, comprimento do segmento e um campo de checksum opcional.

5. Checksum para Confiança:

Oferece um campo de checksum opcional para detecção de erros, somando-se ao cabeçalho, dados e um pseudocabeçalho conceitual do IP.

6. Sem Controle de Fluxo ou Retransmissão:

Ao contrário do TCP, o UDP não realiza controle de fluxo, controle de congestionamento ou retransmissão após a chegada de segmentos incorretos. Essas responsabilidades são delegadas aos processos de usuário.

7. Aplicações Cliente-Servidor:

Adequado para aplicações onde o cliente envia solicitações curtas e espera respostas curtas do servidor, como no caso do DNS (Domain Name System).

8. Eficiência em Comunicações Simples:

Enquanto aplicações que exigem controle preciso sobre o fluxo, erros ou sincronização podem optar por TCP, o UDP é eficiente em situações onde menos mensagens e preparação inicial são necessárias.

# 2.3 Relógio Lógico - Relógio de Lamport

Em sistemas distribuídos, onde múltiplos processos operam independentemente, a coordenação temporal é crucial para garantir a consistência e a ordem das operações. O Relógio Lógico de Lamport, proposto por Leslie Lamport em 1978, é uma abordagem para estabelecer uma noção parcial de ordem entre eventos em sistemas distribuídos, sem depender de relógios físicos precisos.

O relógio de Lamport se aplica em ambientes distribuídos permitindo que cada evento em um processo seja marcado com um carimbo de tempo lógico. Essa marcação é uma tupla de dois elementos: o tempo local do processo e o identificador único do processo, desse modo estabelece-se uma relação de ordem parcial entre eventos, caso o evento A precede o evento B, então o carimbo de tempo lógico de A é menor que o de B, fazendo com que sempre que se ocorre um evento, o carimbo de tempo do processo é incrementado. No entanto, embora eficaz para estabelecer uma ordem parcial entre eventos, o Relógio Lógico de Lamport não lida com as variações nos atrasos de comunicação nem com os desvios nos relógios físicos dos processos.

# 2.4 Criptografia

A criptografia, derivada das palavras gregas para "escrita secreta", possui uma longa história de milhares de anos, desempenhando um papel crucial em contextos militares, diplomáticos, memorativos e românticos. Antes dos computadores, as limitações incluíam a habilidade dos criptografistas em realizar transformações, frequentemente em ambientes desafiadores, como em guerras, por exemplo, tornando necessária a alteração de métodos criptográficos rapidamente, em resposta às ameaças, resultando em grande desafios.

Os modelos criptográficos evoluiram bastante ao longo da sua tragetória, o modelo tradicional envolve a transformação de texto simples para texto cifrado através de uma função parametrizada pela chave. O texto cifrado é transmitido, mesmo que o intruso o escute, sem poder decifrá-lo devido à ausência da chave, porém para esse trabalho foi utilizado o modelo de chave pública, o qual foi uma inovação crucial no mundo criptográfico, no qual existem duas chaves diferentes: uma chave pública utilizada para criptografar e uma chave privada para descriptografar, permitindo comunicações seguras sem a necessidade de compartilhar a chave privada. A figura 2 representa o esquemático do modelo criptografico de chave pública.

![Figura 2: Modelo de chave pública](https://www.universidadejava.com.br/images/2020-05-23-criptografia-assimetrica-01.png)

<p align="center">
  <em>https://www.universidadejava.com.br/images/2020-05-23-criptografia-assimetrica-01.png</em><br>
  <em>Figura 2: Modelo de chave pública</em>
</p>

# 2.5 Base64

Base64 é um esquema de codificação que representa dados binários de forma textual. Ele converte sequências de bytes (dados binários) em uma sequência de caracteres ASCII. O termo "64" indica que cada bloco de dados de 8 bits é representado usando 64 caracteres diferentes, geralmente escolhidos de um conjunto predefinido de caracteres ASCII. É frequentemente utilizado para codificar dados binários, como imagens, arquivos anexos de e-mails, ou qualquer tipo de dado binário que precise ser transmitido através de protocolos de texto, como HTTP, XML, ou em campos de dados de formulários HTML.

# 2.6 Confiabilidade

O ambiente da Internet é propenso a falhas, tanto em termos de mensagens quanto de processos, adotar uma abordagem que leve em consideração o modelo de falhas na comunicação é crucial para garantir a confiabilidade do sistema, mesmo em situações adversas em que um dos nós, ou seja, peers apresentem falhas ou estejam indisponíveis. 

A implementação de estratégias robustas para realizar o tratamento de falhas, manter a consistência dos dados e garantir a recuperação eficiente do sistema em face de perturbações é papel da confiabilidade em sistemas distribuídos P2P.

# 2.7 NACK 

O uso do NACK (Negative Acknowledgment) em sistemas de comunicação é uma técnica essencial para garantir a confiabilidade na entrega de mensagens. O NACK é enviado por um receptor para indicar que uma mensagem não foi recebida corretamente ou foi perdida durante a transmissão. Ao receber um NACK, o remetente pode reenviar a mensagem, garantindo que ela seja entregue com sucesso.

Uma das vantagens do uso do NACK é a sua eficiência em situações de perda de pacotes. Em vez de esperar por um timeout para retransmitir a mensagem, o NACK permite uma detecção mais rápida de falhas e uma recuperação mais ágil. Isso ajuda a reduzir o tempo de espera e a melhorar o desempenho da comunicação.

Além disso, o NACK pode ser usado em conjunto com outros mecanismos de confiabilidade, como o ACK (Acknowledgment), para garantir a entrega confiável de mensagens em ambientes de comunicação complexos. Sua implementação adequada pode contribuir significativamente para a robustez e eficácia de um sistema de comunicação, tornando-o uma ferramenta valiosa para garantir a integridade e a confiabilidade das mensagens transmitidas.

# 2.8 Heartbeat

O método Heartbeat é uma técnica utilizada em sistemas de comunicação para monitorar a disponibilidade e a integridade dos nós da rede. Ele consiste no envio periódico de mensagens de "batimento cardíaco" (heartbeats) entre os nós, indicando que estão ativos e operacionais. Se um nó não enviar um heartbeat dentro de um intervalo de tempo predefinido, ele é considerado indisponível ou com falha.

O seu uso é crucial em ambientes onde a detecção rápida de falhas e a manutenção da disponibilidade são essenciais, como em sistemas distribuídos, redes de computadores e comunicações em tempo real. Ele ajuda a identificar problemas de conectividade, congestionamento de rede e falhas de hardware ou software, permitindo uma resposta rápida e eficaz para restaurar a operação normal do sistema.

Além disso, o método Heartbeat pode ser combinado com outros mecanismos de confiabilidade, como o ACK (Acknowledgment) e o NACK (Negative Acknowledgment), para garantir a entrega confiável de mensagens e a detecção de falhas em ambientes complexos. Sua implementação adequada pode contribuir significativamente para a estabilidade e o desempenho de um sistema de comunicação, tornando-o uma prática recomendada em projetos que exigem alta disponibilidade e confiabilidade.

# 3. Resultados e Discussões

O desenvolvimento do software de troca de mensagens baseado no modelo peer-to-peer (P2P) com a utilização do socket UDP e tendo a preocupação para o tratamento de falhas na comunicação resultou em êxito na solução inovadora. O ambiente descentralizado promoveu a aplicação uma resolução eficiente as metas e desafios específicos, com diversas vantagens relacionadas ao contexto a que se encontra.

Tendo em foco o desempenho do sistema utilizou-se o socket UDP, o tipo de conexão que o UDP oferece é totalmente voltada para o âmbito do envio/recebimento de mensagens instantânes, pois a rapidez é um ponto primordial para a troca de dados nesse contexto. No quesito segurança da comunicação, a não utilização de um ponto fixo de consetração de dados em um servidor central é positivo, uma vez que não há um nó único de falha, também a garamtia da confidencialidade das mensagens devido a utilização de chaves criptográficas, faz com que se tenha uma camada a mais de segurança.

A confiabilidade do sistema é significativamente reforçada pela capacidade de gerenciar falhas, onde tanto mensagens quanto processos podem apresentar erros. A combinação do uso do método HEARTBEAT, que monitora a disponibilidade dos nós da rede, com o uso do NACK (Negative Acknowledgment), que indica a necessidade de retransmissão de mensagens não recebidas corretamente, permite uma detecção rápida de falhas e uma recuperação eficiente. Essa abordagem aumenta a usabilidade ao garantir que as mensagens não visualizadas durante períodos de desconexão sejam exibidas quando o usuário se reconectar.

Além disso, a garantia da manutenção da ordem das mensagens sem depender da sincronia com relógios físicos, evitando o uso de servidores temporais, é fundamental. O sistema descarta pontos de falha centralizados, garantindo a descentralização e a confiabilidade sem depender de infraestruturas centralizadas. Essa abordagem oferece flexibilidade e adaptabilidade, atendendo à prioridade de segurança e comunicação eficiente em sistemas P2P de mensagens instantâneas.

A diferença entre o primeiro projeto, que não abordava a confiabilidade na entrega das mensagens, e o atual, que implementa o uso do NACK e do método HEARTBEAT, é significativa em termos de robustez e confiabilidade do sistema. No primeiro projeto, as mensagens perdidas devido à indisponibilidade de um usuário poderiam permanecer perdidas ou fora de ordem, sem garantias de entrega. Isso poderia resultar em falhas na comunicação e na experiência do usuário, especialmente em ambientes empresariais onde a troca de informações é crítica.

Com a inclusão do NACK e do método HEARTBEAT, o sistema agora é capaz de detectar e corrigir automaticamente mensagens perdidas devido à indisponibilidade temporária de um usuário. O NACK permite que o remetente saiba que uma mensagem não foi recebida corretamente e, assim, possa reenviá-la. O método HEARTBEAT, por sua vez, monitora a disponibilidade dos nós da rede, garantindo que os usuários estejam ativos e prontos para receber mensagens. Isso aumenta a confiabilidade do sistema, garantindo que as mensagens sejam entregues corretamente e em ordem, mesmo em ambientes propensos a falhas.

Portanto, a inclusão desses mecanismos de confiabilidade no sistema P2P de mensagens instantâneas representa um avanço significativo em relação ao projeto anterior, garantindo uma comunicação mais robusta, confiável e eficiente para os usuários.

# 4. Conclusão

O desenvolvimento bem-sucedido do sistema de mensagens ZapZaps representa um avanço significativo no campo da comunicação empresarial. Os resultados obtidos destacam a eficácia e eficiência da abordagem P2P em oferecer uma solução segura e confiável para a troca de mensagens em grupos de usuários. A integração dos mecanismos de confiabilidade, como o NACK (Negative Acknowledgment) e o método HEARTBEAT, desempenha um papel fundamental nesse sucesso, garantindo que as mensagens sejam entregues corretamente e em ordem, mesmo em ambientes propensos a falhas.

Este modelo pode servir como base para futuras inovações e melhorias na comunicação de empresas em qualquer área. À medida que a tecnologia continua a avançar, é provável que esse sistema se torne ainda mais sofisticado e eficiente. A integração de tecnologias modernas e a adoção de protocolos de comunicação podem transformar a forma como as pessoas se comunicam, tornando a experiência de troca de mensagens conveniente e eficaz.

No entanto, melhorias futuras devem se concentrar na questão da confiabilidade, especialmente na detecção e tratamento de mensagens perdidas na rede. A evolução contínua do ZapZaps pode resultar em um sistema ainda mais confiável e adaptável às necessidades das empresas, garantindo uma comunicação eficiente e segura.

# 5. Referência:
- TANENBAUM, Andrew S. Redes de Computadores. Pearson, 2014.
- SISTEMAS DISTRIBUÍDOS. CAPÍTULO 6 – SINCRONIZAÇÃO. Slides cedidos pela professora Aline Nascimento e Slides de COS 418: Distributed Systems. http://profs.ic.uff.br/~simone/sd/contaulas/aula12.pdf. Acessado em: 16 de Fevereiro de 2024.
