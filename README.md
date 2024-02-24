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

No código, a recepção de uma mensagem NACK é tratada da seguinte forma:
```
            elif decoded_data.startswith("[NACK:") and decoded_data.endswith("]"):
                _, hash_nack = decoded_data[1:-1].split(":")
                if hash_nack in mensagens_recebidas:
                    for dest_ip in mensagens_recebidas[hash_nack]:
                        peer_socket.sendto(mensagens[hash_nack].encode('utf-8'), (dest_ip, dest_port))
```

`elif decoded_data.startswith("[NACK:") and decoded_data.endswith("]"):`: Verifica se a mensagem recebida é do tipo NACK, ou seja, se começa com `[NACK:` e termina com `]`.

`_, hash_nack = decoded_data[1:-1].split(":")`: Extrai o hash da mensagem NACK para identificar a mensagem original que precisa ser retransmitida.

`if hash_nack in mensagens_recebidas:`: Verifica se o hash da mensagem está na lista de mensagens recebidas.

`for dest_ip in mensagens_recebidas[hash_nack]:`: Para cada destinatário que não recebeu a mensagem original, reenvia a mensagem original para esse destinatário.

Este trecho de código verifica se a mensagem recebida é um NACK e, se for, reenvia a mensagem original para os destinatários que não a receberam corretamente. Isso garante que a mensagem seja entregue a todos os destinatários, aumentando a confiabilidade do sistema de mensagens.

Outro mecanismo de confirmação de entrega de mensagens que trabalha em conjunto com o Nack é implementado no código abaixo:

```
                    # Aguarda a confirmação de todos os receptores
                    start_time = time.time()
                    while True:
                        if all(len(mensagens_recebidas.get(msg_hash, [])) == len(dest_ips) for msg_hash in mensagens_pendentes):
                            break
                        if time.time() - start_time > 5:  # Timeout de 5 segundos
                            print("Timeout: mensagem não entregue para todos os receptores")
                            break
```

Quando uma mensagem é enviada, o remetente espera receber uma confirmação de todos os receptores de que a mensagem foi entregue com sucesso. A variável ```mensagens_pendentes``` mantém o hash das mensagens enviadas que ainda não receberam confirmação de todos os receptores. O código aguarda até que todas as mensagens na lista ```mensagens_pendentes``` tenham sido recebidas por todos os destinatários antes de prosseguir.

O loop ```while``` aguarda continuamente até que todas as mensagens na lista ```mensagens_pendentes``` tenham sido confirmadas ou até que ocorra um timeout de 5 segundos. Se o timeout ocorrer, uma mensagem de erro é exibida indicando que a mensagem não foi entregue a todos os receptores.

# 2.3 Heartbeat

O método Heartbeat é uma técnica utilizada em sistemas de comunicação para monitorar a disponibilidade e a integridade dos nós da rede. Ele consiste no envio periódico de mensagens de "batimento cardíaco" (heartbeats) entre os nós, indicando que estão ativos e operacionais. Se um nó não enviar um heartbeat dentro de um intervalo de tempo predefinido, ele é considerado indisponível ou com falha.

O seu uso é crucial em ambientes onde a detecção rápida de falhas e a manutenção da disponibilidade são essenciais, como em sistemas distribuídos, redes de computadores e comunicações em tempo real. Ele ajuda a identificar problemas de conectividade, congestionamento de rede e falhas de hardware ou software, permitindo uma resposta rápida e eficaz para restaurar a operação normal do sistema.

Além disso, o método Heartbeat pode ser combinado com outros mecanismos de confiabilidade, como o ACK (Acknowledgment) e o NACK (Negative Acknowledgment), para garantir a entrega confiável de mensagens e a detecção de falhas em ambientes complexos. Sua implementação adequada pode contribuir significativamente para a estabilidade e o desempenho de um sistema de comunicação, tornando-o uma prática recomendada em projetos que exigem alta disponibilidade e confiabilidade.

No código, a função para o Heartbeat é a seguinte:

```
def send_heartbeats(peer_socket):

    while True:
        try:
            if peer_socket.fileno() == -1:
                break
            heartbeat_message = "HEARTBEAT"
            for dest_ip in dest_ips:
                peer_socket.sendto(heartbeat_message.encode('utf-8'), (dest_ip, dest_port))
                last_activities[dest_ip] = time.time()  # Atualiza o tempo do último heartbeat enviado
            time.sleep(0.5)

            # Verifica se algum usuário parou de enviar HEARTBEATs
            offline_destinos = [dest_ip for dest_ip in dest_ips if time.time() - last_activities.get(dest_ip, 0) > 10]
            if offline_destinos:
                print("Um ou mais usuários pararam de enviar HEARTBEATs. Encerrando o chat.")
                os._exit(1)  # Encerra o programa

        except socket.errror as e:
            if e.errno == 101:
                print("Erro ao enviar HEARTBEAT: Rede inacessível")
                time.sleep(20)
            else:
                print(f"Erro ao enviar heartbeat: {e}")
```

A função send_heartbeats é responsável por enviar periodicamente mensagens de "batimento cardíaco" (heartbeats) para os nós da rede no sistema de mensagens instantâneas P2P. Esses heartbeats são usados para monitorar a disponibilidade e a integridade dos nós, indicando que estão ativos e operacionais. Se um nó não enviar um heartbeat dentro de um intervalo de tempo predefinido, ele é considerado indisponível ou com falha.

No código, a função utiliza um loop infinito `(while True)` para enviar heartbeats para todos os nós da rede `(dest_ips)`. Ela verifica se o socket está fechado `(peer_socket.fileno() == -1)` e, se estiver, encerra o loop. Em seguida, ela itera sobre todos os IPs de destino `(dest_ips)` e envia um heartbeat para cada um deles usando o método sendto do socket UDP.

Após enviar os heartbeats, a função atualiza o tempo do último heartbeat enviado para cada nó no dicionário last_activities. Em seguida, ela aguarda por um curto período de tempo (0.5 segundos) antes de enviar o próximo heartbeat.

A função também verifica se algum nó parou de enviar heartbeats, identificando os nós que não enviaram heartbeats dentro do intervalo de tempo (1 segundo) `(offline_destinos)`. Se algum nó estiver offline, a função exibe uma mensagem de aviso e encerra o programa usando `os._exit(1)`.

Essa função é essencial para manter a integridade e a disponibilidade do sistema de mensagens instantâneas P2P, garantindo que os nós da rede estejam ativos e operacionais. Ela ajuda a identificar rapidamente problemas de conectividade e falhas de nós, permitindo uma resposta rápida para restaurar a operação normal do sistema.

Foi implementada uma thread para a função send_heartbeats:

```
heartbeats_thread = threading.Thread(target=send_heartbeats, args=(peer_socket,))
heartbeats_thread.start()
```

A forma de verificar o recebimento do Hearbeat no código é a seguinte:

```
# Verifica se algum destinatário está offline (não enviou HEARTBEAT recentemente)
offline_destinos = [dest_ip for dest_ip in dest_ips if time.time() - last_heartbeats[dest_ip] > 1]

if offline_destinos:
    print("Mensagem não entregue para todos os receptores, não será enviada para nenhum.")
```

Este trecho de código verifica se algum dos destinatários está offline, ou seja, se não enviou um "HEARTBEAT" recentemente. Se algum destinatário estiver offline, a mensagem não será enviada para nenhum destinatário, e uma mensagem será exibida informando isso.

```
# Lista para armazenar os tempos do último HEARTBEAT recebido de cada destinatário
last_heartbeats = {dest_ip: time.time() for dest_ip in dest_ips}
```

Esse trecho de código cria um dicionário chamado last_heartbeats que é usado para armazenar os tempos do último "HEARTBEAT" recebido de cada destinatário. A estrutura {dest_ip: time.time() for dest_ip in dest_ips} é uma compreensão de dicionário em Python, onde dest_ip é a chave e time.time() é o valor associado a essa chave.

Essa estrutura é útil para rastrear quando foi o último "HEARTBEAT" recebido de cada destinatário, o que é essencial para verificar a disponibilidade dos nós na rede e tomar medidas adequadas se um nó estiver inativo por muito tempo.

Outro trecho do código usado para auxiliar no controle do Heartbeat:

```
            if decoded_data == "HEARTBEAT":
                last_heartbeats[addr[0]] = time.time()  # Atualiza o tempo do último heartbeat recebido
                continue
```

Nesse código verifica se a mensagem recebida é um "HEARTBEAT". Se for, ele atualiza o tempo do último "HEARTBEAT" recebido do endereço IP addr[0] no dicionário ```last_heartbeats```. Isso é feito para garantir que o sistema mantenha o controle de quando cada nó na rede enviou seu último "HEARTBEAT", permitindo assim a detecção de nós que podem estar inativos ou indisponíveis. O continue é usado para pular o restante do loop de recebimento de mensagens e ir para a próxima iteração, uma vez que não há mais ações específicas a serem tomadas para mensagens "HEARTBEAT".

# 3. Resultados e Discussões

O desenvolvimento do software de troca de mensagens baseado no modelo peer-to-peer (P2P) com a utilização do socket UDP e tendo a preocupação para o tratamento de falhas na comunicação resultou em êxito na solução inovadora. O ambiente descentralizado promoveu a aplicação uma resolução eficiente as metas e desafios específicos, com diversas vantagens relacionadas ao contexto a que se encontra.

A confiabilidade do sistema é significativamente reforçada pela capacidade de gerenciar falhas, onde tanto mensagens quanto processos podem apresentar erros. A combinação do uso do método HEARTBEAT, que monitora a disponibilidade dos nós da rede, com o uso do NACK (Negative Acknowledgment), que indica a necessidade de retransmissão de mensagens não recebidas corretamente, permite uma detecção rápida de falhas e uma recuperação eficiente.

O sistema descarta pontos de falha centralizados, garantindo a descentralização e a confiabilidade sem depender de infraestruturas centralizadas. Essa abordagem oferece flexibilidade e adaptabilidade, atendendo à prioridade de segurança e comunicação eficiente em sistemas P2P de mensagens instantâneas.

A diferença entre o primeiro projeto, que não abordava a confiabilidade na entrega das mensagens, e o atual, que implementa o uso do NACK e do método HEARTBEAT, é significativa em termos de robustez e confiabilidade do sistema. No primeiro projeto, as mensagens perdidas devido à indisponibilidade de um usuário poderiam permanecer perdidas ou fora de ordem, sem garantias de entrega. Isso poderia resultar em falhas na comunicação e na experiência do usuário, especialmente em ambientes empresariais onde a troca de informação é crítica.

Com a inclusão do NACK e do método HEARTBEAT, o sistema agora é capaz de detectar e corrigir automaticamente mensagens perdidas devido à indisponibilidade temporária de um usuário. O NACK permite que o remetente saiba que uma mensagem não foi recebida corretamente e, assim, possa reenviá-la. O método HEARTBEAT, por sua vez, monitora a disponibilidade dos nós da rede, garantindo que os usuários estejam ativos e prontos para receber mensagens. Isso aumenta a confiabilidade do sistema, garantindo que as mensagens sejam entregues corretamente e em ordem, mesmo em ambientes propensos a falhas.

Portanto, a inclusão desses mecanismos de confiabilidade no sistema P2P de mensagens instantâneas representa um avanço significativo em relação ao projeto anterior, garantindo uma comunicação mais robusta e confiável para os usuários.

A implementação atual do sistema adota uma abordagem de pausar o chat e aguardar o retorno do usuário que estava offline para retomar a entrega de mensagens. Embora essa abordagem seja eficaz em garantir que o usuário não perca nenhuma mensagem, ela pode ser considerada não eficiente em termos de experiência do usuário. O ideal seria que o chat continuasse funcionando normalmente e, quando o usuário retornasse, ele receberia as mensagens que foram enviadas durante sua ausência.

# 4. Conclusão

O desenvolvimento bem-sucedido do sistema de mensagens ZapZaps representa um avanço significativo no campo da comunicação empresarial. Os resultados obtidos destacam a eficácia e eficiência da abordagem P2P em oferecer uma solução segura e confiável para a troca de mensagens em grupos de usuários. A integração dos mecanismos de confiabilidade, como o NACK (Negative Acknowledgment) e o método HEARTBEAT, desempenha um papel fundamental nesse sucesso, garantindo que as mensagens sejam entregues corretamente e em ordem, mesmo em ambientes propensos a falhas.

Este modelo pode servir como base para futuras inovações e melhorias na comunicação de empresas em qualquer área. À medida que a tecnologia continua a avançar, é provável que esse sistema se torne ainda mais sofisticado e eficiente. A integração de tecnologias modernas e a adoção de protocolos de comunicação podem transformar a forma como as pessoas se comunicam, tornando a experiência de troca de mensagens conveniente e eficaz.

No entanto, melhorias futuras devem se concentrar na questão da confiabilidade, do chat e do tratamento das mensagens, especialmente quando um usuário estiver offline. A evolução contínua do ZapZaps pode resultar em um sistema ainda mais confiável e adaptável às necessidades das empresas, garantindo uma comunicação eficiente e segura.

# 5. Referência:
- TANENBAUM, Andrew S. Redes de Computadores. Pearson, 2014.
- Kurose|Ross. Redes de Computadores e a internet, uma abordagem top-down. Pearson, 2014.
- https://ensinar.wordpress.com/2008/12/01/o-que-e-heartbeat/. Acessado em 15 de Fevereiro de 2024.
