# Supported Providers

*Last modified: 2026-04-14*

SBproxy supports **203+ AI providers** natively, plus any OpenAI-compatible API via the `generic` provider type.

## Provider List

| Name | Provider | Format | Capabilities | Documentation |
|------|----------|--------|--------------|---------------|
| `abeja` | ABEJA Platform | custom | - | [Docs](https://abeja.io) |
| `ai21` | AI21 Labs | openai | streaming, tools (256k) | [Docs](https://docs.ai21.com) |
| `ai21_studio` | AI21 Studio (Jamba) | custom | streaming, tools (256k) | [Docs](https://docs.ai21.com) |
| `ai_singapore` | AI Singapore (SEA-LION) | openai | - | [Docs](https://aisingapore.org) |
| `aleph_alpha` | Aleph Alpha | openai | - | [Docs](https://docs.aleph-alpha.com) |
| `alibaba` | Alibaba Cloud (DashScope) | openai | streaming, tools (128k) | [Docs](https://help.aliyun.com/zh/dashscope/) |
| `alibaba_eas` | Alibaba PAI-EAS | openai | streaming (varies) | [Docs](https://www.alibabacloud.com/help/en/pai) |
| `aliyun_bailian` | Aliyun Bailian | custom | streaming (varies) | [Docs](https://bailian.console.aliyun.com) |
| `anthropic` | Anthropic | anthropic | streaming, tools, vision (200k) | [Docs](https://docs.anthropic.com) |
| `anyscale` | Anyscale | openai | streaming (varies) | [Docs](https://docs.endpoints.anyscale.com) |
| `arcee` | Arcee AI | openai | - | [Docs](https://arcee.ai) |
| `arliai` | Arli AI | openai | - | [Docs](https://www.arliai.com) |
| `assemblyai` | AssemblyAI | openai | audio | [Docs](https://www.assemblyai.com/docs) |
| `avian` | Avian.io | openai | - | [Docs](https://avian.io/docs) |
| `aws_comprehend` | AWS Comprehend | custom | - | [Docs](https://docs.aws.amazon.com/comprehend) |
| `azure` | Azure OpenAI | azure | streaming, tools, vision, embeddings, audio (128k) | [Docs](https://learn.microsoft.com/en-us/azure/ai-services/openai/) |
| `azure_ml` | Azure ML Endpoints | openai | streaming, tools (varies) | [Docs](https://learn.microsoft.com/en-us/azure/machine-learning/) |
| `baai` | BAAI (Beijing Academy of AI) | custom | - | [Docs](https://www.baai.ac.cn) |
| `baichuan` | Baichuan AI | openai | streaming, tools (128k) | [Docs](https://platform.baichuan-ai.com/docs) |
| `baidu` | Baidu (ERNIE/Qianfan) | openai | streaming, tools (varies) | [Docs](https://cloud.baidu.com/doc/WENXINWORKSHOP/index.html) |
| `banana` | Banana.dev | custom | - | [Docs](https://docs.banana.dev) |
| `baseten` | Baseten | openai | streaming (varies) | [Docs](https://docs.baseten.co) |
| `beam` | Beam Cloud | openai | - | [Docs](https://beam.cloud) |
| `bedrock` | AWS Bedrock | bedrock | streaming, tools, vision (varies) | [Docs](https://docs.aws.amazon.com/bedrock/) |
| `bentoml` | BentoML Cloud | openai | streaming (varies) | [Docs](https://docs.bentoml.com) |
| `black_forest_labs` | Black Forest Labs (FLUX) | custom | vision | [Docs](https://docs.bfl.ml) |
| `braintrust` | Braintrust Proxy | openai | streaming, tools (varies) | [Docs](https://www.braintr.us/docs) |
| `centml` | CentML | openai | streaming (varies) | [Docs](https://centml.ai/docs) |
| `cerebras` | Cerebras | openai | streaming (8k) | [Docs](https://inference-docs.cerebras.ai) |
| `cerebrium` | Cerebrium | openai | streaming (varies) | [Docs](https://docs.cerebrium.ai) |
| `character_ai` | Character.AI | custom | - | [Docs](https://character.ai) |
| `chutes` | Chutes AI | openai | streaming (varies) | [Docs](https://chutes.ai) |
| `cloudflare_ai` | Cloudflare Workers AI | openai | streaming (varies) | [Docs](https://developers.cloudflare.com/workers-ai/) |
| `codeium` | Codeium (Windsurf) | custom | - | [Docs](https://codeium.com) |
| `codestral` | Codestral (Mistral Code) | openai | streaming, tools (128k) | [Docs](https://docs.mistral.ai/capabilities/code_generation) |
| `cohere` | Cohere | openai | streaming, tools, embeddings (128k) | [Docs](https://docs.cohere.com) |
| `contextual_ai` | Contextual AI | custom | - | [Docs](https://contextual.ai) |
| `continue_dev` | Continue | openai | streaming (varies) | [Docs](https://docs.continue.dev) |
| `corcel` | Corcel AI | openai | streaming (varies) | [Docs](https://corcel.io) |
| `coreweave` | CoreWeave Inference | openai | - | [Docs](https://coreweave.com) |
| `coze` | Coze (ByteDance) | custom | - | [Docs](https://www.coze.com) |
| `crusoe` | Crusoe AI Cloud | openai | streaming (varies) | [Docs](https://crusoe.ai) |
| `cyberagent` | CyberAgent AI (CALM) | custom | - | [Docs](https://www.cyberagent.co.jp) |
| `dashscope` | DashScope (Alibaba Cloud) | openai | streaming, tools (128k) | [Docs](https://dashscope.aliyun.com) |
| `databricks` | Databricks | openai | streaming, tools (128k) | [Docs](https://docs.databricks.com/en/machine-learning/model-serving/) |
| `deepinfra` | DeepInfra | openai | streaming, tools (varies) | [Docs](https://deepinfra.com/docs) |
| `deepl` | DeepL | custom | - | [Docs](https://developers.deepl.com) |
| `deepseek` | DeepSeek | openai | streaming, tools (128k) | [Docs](https://platform.deepseek.com/api-docs) |
| `dify` | Dify.AI | custom | - | [Docs](https://dify.ai) |
| `elevenlabs` | ElevenLabs | openai | streaming, audio | [Docs](https://elevenlabs.io/docs) |
| `elyza` | ELYZA | openai | - | [Docs](https://elyza.ai) |
| `empower` | Empower AI | openai | - | [Docs](https://empower.dev) |
| `ernie` | Baidu ERNIE Bot | custom | streaming, tools (varies) | [Docs](https://cloud.baidu.com/doc/WENXINWORKSHOP) |
| `exllamav2` | ExLlamaV2 | openai | streaming (varies) | [Docs](https://github.com/turboderp/exllamav2) |
| `fal` | fal.ai | custom | vision | [Docs](https://fal.ai/docs) |
| `featherless` | Featherless AI | openai | streaming (varies) | [Docs](https://featherless.ai/docs) |
| `featherless_serverless` | Featherless Serverless | openai | streaming (varies) | [Docs](https://featherless.ai) |
| `fireworks` | Fireworks AI | openai | streaming, tools (128k) | [Docs](https://docs.fireworks.ai) |
| `forefront` | Forefront AI | openai | streaming (varies) | [Docs](https://docs.forefront.ai) |
| `friendli` | Friendli AI | openai | streaming, tools (varies) | [Docs](https://friendli.ai/docs) |
| `friendli_serverless` | FriendliAI Serverless | openai | streaming, tools (varies) | [Docs](https://docs.friendli.ai) |
| `g42` | G42 AI (Jais) | openai | streaming (varies) | [Docs](https://g42.ai) |
| `gaianet` | GaiaNet | openai | streaming (varies) | [Docs](https://docs.gaianet.ai) |
| `gilas` | Gilas AI | openai | streaming (varies) | [Docs](https://gilas.io) |
| `gladia` | Gladia | custom | audio | [Docs](https://docs.gladia.io) |
| `glhf` | GLHF Chat | openai | streaming (varies) | [Docs](https://glhf.chat) |
| `google` | Google AI (Gemini) | openai | streaming, tools, vision, embeddings (1M) | [Docs](https://ai.google.dev/docs) |
| `google_ai_studio` | Google AI Studio | custom | streaming, tools, vision (1M) | [Docs](https://ai.google.dev) |
| `goose_ai` | GooseAI | openai | streaming (varies) | [Docs](https://goose.ai/docs) |
| `gpt4all` | GPT4All | openai | streaming (varies) | [Docs](https://docs.gpt4all.io) |
| `gradient` | Gradient AI | custom | - | [Docs](https://gradient.ai) |
| `groq` | Groq | openai | streaming, tools (128k) | [Docs](https://console.groq.com/docs) |
| `helicone` | Helicone | openai | streaming, tools (varies) | [Docs](https://docs.helicone.ai) |
| `huggingface_api` | Hugging Face Inference API | openai | streaming (varies) | [Docs](https://huggingface.co/docs/api-inference) |
| `huggingface_endpoints` | Hugging Face Inference Endpoints | openai | streaming (varies) | [Docs](https://huggingface.co/docs/inference-endpoints) |
| `hunyuan` | Tencent Hunyuan | custom | streaming, tools (varies) | [Docs](https://cloud.tencent.com/product/hunyuan) |
| `hyperbolic` | Hyperbolic | openai | streaming (varies) | [Docs](https://docs.hyperbolic.xyz) |
| `ibm_granite` | IBM Granite | custom | streaming (varies) | [Docs](https://www.ibm.com/granite) |
| `ideogram` | Ideogram | custom | vision | [Docs](https://developer.ideogram.ai) |
| `iflyrec` | iFlytek Spark | openai | streaming (varies) | [Docs](https://www.xfyun.cn/doc/spark) |
| `iflytek` | iFlytek (Spark) | openai | streaming (varies) | [Docs](https://xinghuo.xfyun.cn/sparkapi) |
| `inference_net` | Inference.net | openai | streaming (varies) | [Docs](https://inference.net) |
| `infomaniak` | Infomaniak AI Tools | openai | streaming (varies) | [Docs](https://developer.infomaniak.com/docs/api/get/1/ai) |
| `internlm` | InternLM (Shanghai AI Lab) | openai | streaming (varies) | [Docs](https://internlm.intern-ai.org.cn/api/document) |
| `jan` | Jan AI | openai | streaming (varies) | [Docs](https://jan.ai/docs) |
| `jina` | Jina AI | openai | embeddings | [Docs](https://jina.ai/docs) |
| `kakao` | Kakao Brain (KoGPT) | custom | - | [Docs](https://kakaobrain.com) |
| `kata_ai` | Kata.ai | custom | - | [Docs](https://kata.ai) |
| `klarna` | Klarna AI | custom | - | [Docs](https://docs.klarna.com) |
| `kluster` | Kluster AI | openai | streaming (varies) | [Docs](https://kluster.ai/docs) |
| `koboldai` | KoboldAI | openai | streaming (varies) | [Docs](https://github.com/KoboldAI/KoboldAI-Client) |
| `kornia` | Kornia AI | openai | - | [Docs](https://kornia.ai) |
| `krutrim` | Krutrim AI (Ola) | openai | streaming (varies) | [Docs](https://krutrim.com) |
| `kunlun_skywork` | Kunlun Tech (Skywork) | custom | streaming (varies) | [Docs](https://tiangong.cn) |
| `lambda` | Lambda | openai | streaming (varies) | [Docs](https://docs.lambdalabs.com) |
| `lamini` | Lamini | openai | streaming (varies) | [Docs](https://lamini.ai) |
| `lelapa` | Lelapa AI | custom | - | [Docs](https://lelapa.ai) |
| `leonardo` | Leonardo AI | openai | vision | [Docs](https://docs.leonardo.ai) |
| `lepton` | Lepton AI | openai | streaming (varies) | [Docs](https://www.lepton.ai/docs) |
| `lightning` | Lightning AI | openai | streaming (varies) | [Docs](https://lightning.ai) |
| `lighton` | LightOn | custom | - | [Docs](https://lighton.ai) |
| `line_clova` | LINE CLOVA (HyperCLOVA X) | custom | - | [Docs](https://clova.ai) |
| `lingyi_wanwu` | Lingyiwanwu (01.AI) | openai | streaming, tools (128k) | [Docs](https://01.ai) |
| `litellm_proxy` | LiteLLM Proxy | openai | streaming, tools (varies) | [Docs](https://docs.litellm.ai/docs/proxy/quick_start) |
| `llamacpp` | llama.cpp Server | openai | streaming, tools (varies) | [Docs](https://github.com/ggerganov/llama.cpp/blob/master/examples/server/README.md) |
| `lmstudio` | LM Studio | openai | streaming, tools (varies) | [Docs](https://lmstudio.ai/docs) |
| `lmsys` | LMSYS (Chatbot Arena) | openai | streaming (varies) | [Docs](https://lmsys.org) |
| `localai` | LocalAI | openai | streaming, tools (varies) | [Docs](https://localai.io/docs) |
| `luma` | Luma AI (Dream Machine) | custom | vision | [Docs](https://docs.lumalabs.ai) |
| `maritaca` | Maritaca AI (Sabia) | openai | streaming (varies) | [Docs](https://maritaca.ai) |
| `martian` | Martian | openai | streaming (varies) | [Docs](https://docs.withmartian.com) |
| `massed_compute` | Massed Compute | openai | streaming (varies) | [Docs](https://massedcompute.com) |
| `megrez` | Infinigence AI (Megrez) | openai | streaming (varies) | [Docs](https://cloud.infini-ai.com) |
| `megvii` | Megvii (Face++) | custom | - | [Docs](https://megvii.com) |
| `minimax` | MiniMax | openai | streaming, tools (128k) | [Docs](https://platform.minimaxi.com/document) |
| `mistral` | Mistral AI | openai | streaming, tools, vision (128k) | [Docs](https://docs.mistral.ai) |
| `mixedbread` | Mixedbread AI | openai | embeddings | [Docs](https://www.mixedbread.ai/docs) |
| `modal` | Modal | openai | streaming (varies) | [Docs](https://modal.com/docs) |
| `modelscope` | ModelScope (Alibaba DAMO) | openai | streaming (varies) | [Docs](https://modelscope.cn) |
| `monster_api` | Monster API | openai | streaming (varies) | [Docs](https://developer.monsterapi.ai) |
| `moonshot` | Moonshot AI (Kimi) | openai | streaming, tools (128k) | [Docs](https://platform.moonshot.cn/docs) |
| `mystic` | Mystic AI (Pipeline) | openai | - | [Docs](https://docs.mystic.ai) |
| `naver` | Naver HyperCLOVA X | openai | streaming, tools (varies) | [Docs](https://api.ncloud-docs.com/docs/ai-naver-clovastudio) |
| `nebius` | Nebius AI Studio | openai | streaming, tools (varies) | [Docs](https://studio.nebius.ai/docs) |
| `neets` | Neets.ai | openai | streaming (varies) | [Docs](https://neets.ai) |
| `nhn_cloud` | NHN Cloud AI | custom | - | [Docs](https://www.nhncloud.com) |
| `nim` | NVIDIA NIM | openai | streaming, tools (128k) | [Docs](https://build.nvidia.com) |
| `nlp_cloud` | NLP Cloud | openai | streaming (varies) | [Docs](https://docs.nlpcloud.com) |
| `nomic` | Nomic AI | openai | embeddings | [Docs](https://docs.nomic.ai) |
| `not_diamond` | Not Diamond | openai | streaming (varies) | [Docs](https://notdiamond.ai) |
| `novita` | Novita AI | openai | streaming (varies) | [Docs](https://novita.ai/docs) |
| `nscale` | Nscale | openai | streaming (varies) | [Docs](https://docs.nscale.com) |
| `nvidia` | NVIDIA NIM | openai | streaming, tools (128k) | [Docs](https://build.nvidia.com/docs) |
| `octoai` | OctoAI | openai | streaming (varies) | [Docs](https://octoai.cloud/docs) |
| `ollama` | Ollama | openai | streaming, tools, vision (varies) | [Docs](https://ollama.ai/docs) |
| `oobabooga` | Oobabooga (text-generation-webui) | openai | streaming (varies) | [Docs](https://github.com/oobabooga/text-generation-webui) |
| `openai` | OpenAI | openai | streaming, tools, vision, embeddings, audio (128k) | [Docs](https://platform.openai.com/docs) |
| `openai_azure_ad` | Azure OpenAI (Entra ID) | openai | streaming, tools, vision, embeddings, audio (128k) | [Docs](https://learn.microsoft.com/en-us/azure/ai-services/openai) |
| `openllm` | OpenLLM (BentoML) | openai | streaming (varies) | [Docs](https://github.com/bentoml/OpenLLM) |
| `openrouter` | OpenRouter | openai | streaming, tools, vision (varies) | [Docs](https://openrouter.ai/docs) |
| `oracle_genai` | Oracle Generative AI | custom | streaming (varies) | [Docs](https://docs.oracle.com/en-us/iaas/Content/generative-ai) |
| `oracle_oci` | Oracle OCI Generative AI | openai | streaming (varies) | [Docs](https://docs.oracle.com/en-us/iaas/Content/generative-ai/home.htm) |
| `paperspace` | Paperspace (DigitalOcean) | custom | - | [Docs](https://www.paperspace.com) |
| `pawan` | PawanOsman API | openai | streaming (varies) | [Docs](https://github.com/PawanOsman/ChatGPT) |
| `perplexity` | Perplexity | openai | streaming (128k) | [Docs](https://docs.perplexity.ai) |
| `phind` | Phind | openai | streaming (varies) | [Docs](https://www.phind.com) |
| `pinecone` | Pinecone Inference | custom | embeddings | [Docs](https://docs.pinecone.io) |
| `poolside` | Poolside AI | openai | streaming (varies) | [Docs](https://poolside.ai) |
| `portkey` | Portkey | openai | streaming, tools (varies) | [Docs](https://portkey.ai/docs) |
| `predibase` | Predibase | openai | streaming (varies) | [Docs](https://docs.predibase.com) |
| `predictionguard` | Prediction Guard | openai | streaming (varies) | [Docs](https://www.predictionguard.com) |
| `preferred_networks` | Preferred Networks (PLaMo) | custom | - | [Docs](https://www.preferred.jp) |
| `qianfan` | Baidu Qianfan | openai | streaming, tools (varies) | [Docs](https://cloud.baidu.com/doc/WENXINWORKSHOP) |
| `qihoo_360` | 360 AI (Zhi Nao) | openai | streaming (varies) | [Docs](https://ai.360.cn) |
| `reka` | Reka AI | openai | streaming, tools (varies) | [Docs](https://docs.reka.ai) |
| `replicate` | Replicate | openai | streaming (varies) | [Docs](https://replicate.com/docs) |
| `replit` | Replit AI | custom | - | [Docs](https://replit.com) |
| `rev_ai` | Rev AI | custom | audio | [Docs](https://docs.rev.ai) |
| `runpod` | RunPod | openai | streaming (varies) | [Docs](https://docs.runpod.io) |
| `runway` | Runway ML | custom | vision | [Docs](https://docs.runwayml.com) |
| `sagemaker` | Amazon SageMaker | openai | streaming (varies) | [Docs](https://docs.aws.amazon.com/sagemaker/) |
| `sakura_internet` | Sakura Internet AI | openai | streaming (varies) | [Docs](https://www.sakura.ad.jp) |
| `salesforce_einstein` | Salesforce Einstein AI | custom | - | [Docs](https://developer.salesforce.com/docs/einstein) |
| `sambanova` | SambaNova | openai | streaming, tools (128k) | [Docs](https://docs.sambanova.ai) |
| `sap_ai` | SAP AI Core | custom | - | [Docs](https://help.sap.com/docs/sap-ai-core) |
| `sarvam` | Sarvam AI | openai | streaming (varies) | [Docs](https://www.sarvam.ai) |
| `sensetime` | SenseTime (SenseNova) | openai | streaming (varies) | [Docs](https://platform.sensenova.cn/doc) |
| `shadeform` | Shadeform | openai | streaming (varies) | [Docs](https://shadeform.ai) |
| `shuttleai` | Shuttle AI | openai | streaming (varies) | [Docs](https://shuttleai.app) |
| `siliconflow` | SiliconFlow | openai | streaming (varies) | [Docs](https://docs.siliconflow.cn) |
| `skelter_labs` | Skelter Labs | custom | - | [Docs](https://www.skelterlabs.com) |
| `snowflake` | Snowflake Arctic (Cortex) | openai | streaming (varies) | [Docs](https://docs.snowflake.com/en/user-guide/snowflake-cortex/llm-functions) |
| `spark` | iFlytek Spark (Legacy) | custom | streaming (varies) | [Docs](https://www.xfyun.cn) |
| `speechmatics` | Speechmatics | custom | audio | [Docs](https://docs.speechmatics.com) |
| `stability` | Stability AI | openai | vision | [Docs](https://platform.stability.ai/docs/api-reference) |
| `stepfun` | Stepfun | openai | streaming, tools (128k) | [Docs](https://platform.stepfun.com/docs) |
| `symbl` | Symbl.ai | custom | - | [Docs](https://docs.symbl.ai) |
| `tabbyml` | TabbyML | openai | streaming (varies) | [Docs](https://tabby.tabbyml.com/docs) |
| `tabnine` | Tabnine | custom | - | [Docs](https://www.tabnine.com) |
| `telnyx` | Telnyx AI | openai | streaming (varies) | [Docs](https://telnyx.com) |
| `tencent` | Tencent Cloud (Hunyuan) | openai | streaming, tools (varies) | [Docs](https://cloud.tencent.com/document/product/1729) |
| `tensordock` | TensorDock | openai | streaming (varies) | [Docs](https://tensordock.com) |
| `textsynth` | TextSynth | openai | streaming (varies) | [Docs](https://textsynth.com/documentation.html) |
| `tgi` | Text Generation Inference (TGI) | openai | streaming (varies) | [Docs](https://huggingface.co/docs/text-generation-inference) |
| `tii_falcon` | Technology Innovation Institute (Falcon) | openai | streaming (varies) | [Docs](https://falconllm.tii.ae) |
| `titan` | Amazon Titan | custom | streaming, embeddings (varies) | [Docs](https://docs.aws.amazon.com/bedrock/latest/userguide/titan-models.html) |
| `together` | Together AI | openai | streaming, tools (128k) | [Docs](https://docs.together.ai) |
| `twelve_labs` | Twelve Labs | custom | vision | [Docs](https://docs.twelvelabs.io) |
| `unify` | Unify AI | openai | streaming (varies) | [Docs](https://unify.ai) |
| `upstage` | Upstage | openai | streaming, embeddings (varies) | [Docs](https://developers.upstage.ai/docs) |
| `vast_ai` | Vast.ai | openai | streaming (varies) | [Docs](https://vast.ai) |
| `vectara` | Vectara | custom | embeddings | [Docs](https://docs.vectara.com) |
| `vercel_ai` | Vercel AI Gateway | openai | streaming (varies) | [Docs](https://sdk.vercel.ai/docs) |
| `vertex` | Google Vertex AI | openai | streaming, tools, vision, embeddings (1M) | [Docs](https://cloud.google.com/vertex-ai/docs) |
| `vllm` | vLLM | openai | streaming, tools (varies) | [Docs](https://docs.vllm.ai) |
| `volcengine` | Volcengine (ByteDance/Doubao) | openai | streaming, tools (varies) | [Docs](https://www.volcengine.com/docs/82379) |
| `voyage` | Voyage AI | openai | embeddings | [Docs](https://docs.voyageai.com) |
| `watsonx` | IBM watsonx | openai | streaming, tools (varies) | [Docs](https://www.ibm.com/docs/en/watsonx) |
| `writer` | Writer | openai | streaming, tools (varies) | [Docs](https://dev.writer.com/api-guides) |
| `xai` | xAI (Grok) | openai | streaming, tools, vision (128k) | [Docs](https://docs.x.ai) |
| `yi` | 01.AI (Yi) | openai | streaming, tools (128k) | [Docs](https://platform.lingyiwanwu.com/docs) |
| `zhipu` | Zhipu AI (GLM) | openai | streaming, tools (128k) | [Docs](https://open.bigmodel.cn/dev/api) |
| `zhipuai` | Zhipu AI (GLM-4) | openai | streaming, tools (128k) | [Docs](https://open.bigmodel.cn) |

**Total: 203 providers**

## Using a Provider

Configure any provider in your `sb.yml`:

```yaml
origins:
  - hostnames:
      - api.example.com
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: ${OPENAI_API_KEY}
          model: gpt-4o
```

## Custom / OpenAI-Compatible Providers

For providers not in this list, use the `generic` type with any OpenAI-compatible endpoint:

```yaml
providers:
  - name: my-provider
    type: generic
    base_url: https://api.example.com/v1
    api_key: ${MY_API_KEY}
    model: my-model
```

