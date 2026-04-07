# 🌡️ Vansan Therm - Monitor de Farmácia (v6.1)

O **Vansan Therm** é um sistema inteligente de monitoramento térmico e de umidade, desenvolvido para garantir a conformidade com a norma **ANVISA RDC 301** em farmácias de manipulação.

## 🚀 Sobre o Projeto
Este sistema utiliza um **ESP32** para monitorar o ambiente em tempo real e controlar automaticamente aparelhos de ar-condicionado (Gree/Elgin) via protocolo **UDP com criptografia AES-128**, dispensando o uso de infravermelho.



## 🛠️ Principais Funcionalidades
* **Monitoramento RDC 301:** Alertas automáticos se a temperatura sair da faixa de 15°C–25°C ou a umidade de 40%–70%.
* **Controle Nativo de AC:** Integração direta com aparelhos Gree/Elgin Eco Inverter II.
* **Interface Web:** Painel de controle acessível via navegador (`vansan.local`).
* **Alertas Remotos:** Notificações instantâneas via **Telegram** e log de dados no **ThingSpeak**.
* **Segurança:** Dados sensíveis protegidos por criptografia AES e armazenamento seguro na memória NVS.

## 🧱 Estrutura do Hardware
| Componente | Função |
| :--- | :--- |
| **ESP32 DevKit V1** | Cérebro do sistema e comunicação Wi-Fi |
| **Sensor DHT22** | Leitura de precisão de temperatura e umidade |
| **LCD 16x2 I2C** | Visualização local dos dados e status do sistema |
| **LEDs de Status** | Sinalização visual de alertas (Verde/Azul/Vermelho) |

## 💻 Como rodar este projeto
1.  Abra a pasta no **VS Code** com a extensão **PlatformIO** instalada.
2.  Configure suas credenciais (Bot Token) no código.
3.  Compile e faça o upload para o seu ESP32.
4.  Conecte-se à rede `VANSAN-CONFIG` para configurar o Wi-Fi da farmácia.

---
*Projeto desenvolvido para o **Empreenda Senac 2026** por Edinaldo Santos de Almeida.*
