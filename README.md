# ZapsZap Release Candidate

# 1. Introdução.

No atual cenário empresarial, a comunicação instantânea desempenha um papel essencial na eficiência e colaboração entre equipes, tornando os aplicativos de mensagens uma ferramenta indispensável. Além de facilitar a troca de informações, esses aplicativos redefinem os padrões de comunicação, oferecendo recursos avançados, como chamadas de vídeo, compartilhamento de arquivos e integração com diversas plataformas. A segurança, garantida pela criptografia de ponta a ponta, é um aspecto crucial para proteger a privacidade das comunicações.

Nesse contexto, uma startup contratou uma equipe de desenvolvimento para criar um software de mensagens instantâneas voltado para o ambiente corporativo, baseado no modelo peer-to-peer (P2P). O desafio inicial era implementar uma solução descentralizada, sem a dependência de um servidor central, permitindo a troca segura de mensagens de texto entre grupos de usuários dentro da empresa.

O protótipo inicial atendeu a esses requisitos, garantindo que as mensagens fossem recebidas apenas uma vez e exibidas na mesma ordem em todas as interfaces dos usuários. Para a próxima versão, além de manter esses requisitos, o sistema deve oferecer um serviço ainda mais confiável. Isso significa que, se uma mensagem for exibida na interface de um usuário, ela também deve ser exibida na interface de todos os outros usuários. Outra adição importante é a capacidade de realizar o tratamento das mensagens não visualizadas durante a desconexão do usuário quando ele se reconectar ao sistema.

# 2. Fundamentação Teórica

Para a construção desse sistema, é fundamental consolidar conceitos já estabelecidos, que foram detalhadamente explicados em um relatório anterior. Nesse novo contexto, serão abordados os conceitos adicionais necessários para o desenvolvimento do projeto atual. Vale ressaltar que os requisitos anteriores, já elucidados no relatório anterior, continuam válidos e serão mantidos. Essa fundamentação abordará os novos conceitos utilizados para o novo projeto, mantendo a base sólida estabelecida anteriormente.

# 2.1 Confiabilidade

A Internet é propensa a falhas, tanto em termos de mensagens quanto de processos. Adotar uma abordagem que leve em consideração o modelo de falhas na comunicação é crucial para garantir a confiabilidade do sistema, especialmente em situações adversas em que um dos nós, ou seja, peers, apresente falhas ou esteja indisponível.

A confiabilidade em sistemas distribuídos P2P envolve a implementação de estratégias robustas para tratar falhas, manter a consistência dos dados e garantir a recuperação eficiente do sistema em face de perturbações. Essas estratégias são essenciais para garantir que as mensagens sejam entregues apenas uma vez e exibidas na mesma ordem em todas as interfaces dos usuários, conforme requerido pelo sistema de mensagens instantâneas e que seja um serviço confiável em que, se uma mensagem for exibida na interface de um determinado usuário, deve também ser exibida na interface dos outros usuários.

# 2.2 NACK 

O uso do NACK (Negative Acknowledgment) em sistemas de comunicação é uma técnica essencial para garantir a confiabilidade na entrega de mensagens. O NACK é enviado por um receptor para indicar que uma mensagem não foi recebida corretamente ou foi perdida durante a transmissão. Ao receber um NACK, o remetente pode reenviar a mensagem, garantindo que ela seja entregue com sucesso.

Uma das vantagens do uso do NACK é a sua eficiência em situações de perda de pacotes. Em vez de esperar por um timeout para retransmitir a mensagem, o NACK permite uma detecção mais rápida de falhas e uma recuperação mais ágil. Isso ajuda a reduzir o tempo de espera e a melhorar o desempenho da comunicação.

Além disso, o NACK pode ser usado em conjunto com outros mecanismos de confiabilidade, como o ACK (Acknowledgment), para garantir a entrega confiável de mensagens em ambientes de comunicação complexos. Sua implementação adequada pode contribuir significativamente para a robustez e eficácia de um sistema de comunicação, tornando-o uma ferramenta valiosa para garantir a integridade e a confiabilidade das mensagens transmitidas.
```
            elif decoded_data.startswith("[NACK:") and decoded_data.endswith("]"):
                _, hash_nack = decoded_data[1:-1].split(":")
                if hash_nack in mensagens_recebidas:
                    for dest_ip in mensagens_recebidas[hash_nack]:
                        peer_socket.sendto(mensagens[hash_nack].encode('utf-8'), (dest_ip, dest_port))```

# 2.3 Heartbeat

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
