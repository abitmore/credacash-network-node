/*
 * CredaCash (TM) cryptocurrency and blockchain
 *
 * Copyright (C) 2015-2024 Creda Foundation, Inc., or its contributors
 *
 * mints.cpp
*/

#include "ccnode.h"
#include "mints.hpp"

using namespace snarkfront;

const bigint_t mint_outputs[MINT_OUTPUTS] = {
	bigint_t("16441857490071664187519527570515753481832400567322073843666688146626804458732"),
	bigint_t("18761844323410935399305869229385398590663483274232650025152097283510616095947"),
	bigint_t("2643267424957448428022693557288536367485463725621195352787225217632757020521"),
	bigint_t("17055001037971734560482044773702923974082782527903699080735797133676936543950"),
	bigint_t("5031762286533598209007409924955341704849678729777548592543160776205753271811"),
	bigint_t("10817061757267113596015143575971918366321359078869388216226756830110059574291"),
	bigint_t("18783326090312245172030577493395841129251072565326592900256394659151404391512"),
	bigint_t("3309496162112016808797748430591679551664336617381883803407160330467447301715"),
	bigint_t("11093804399870958889870371355079737616590045996946093023790072070155502679274"),
	bigint_t("21346754728464801712136873468558126063079096297215756587400724486724483352071"),
	bigint_t("8525779617056027174392791611118738114154111364291684804071631034408856811875"),
	bigint_t("1377555005488869151258377045334520052918550525745275621165107660256097921979"),
	bigint_t("9484481304961378164241658568605312579634946842866324290753647605707060627992"),
	bigint_t("5695509973448777753445362206756693206366959839692792483113599313848293291515"),
	bigint_t("14006868774629096430738705703593291760804019240544292068236489545891432829464"),
	bigint_t("3127623812690784945773655243387373587114446487839773785357516887934995423317"),
	bigint_t("20184814153492912273830068704380609301270778400197844597609506051511030330403"),
	bigint_t("21675183967275237965802382187446574801937874848772472106050693390513681180885"),
	bigint_t("17852963513252013061841840585780678908008789747770065418612969358644991596308"),
	bigint_t("300594722791881237568927704900289413215164708623279905577714060307823790765"),
	bigint_t("16610860625984147412822720453177830497833850664246751305429058579620873362167"),
	bigint_t("5854044466092547902239591841904762465751385371135387214621264596044655181158"),
	bigint_t("21440777615821832003903624502169688493530528322803307103826592526417904242795"),
	bigint_t("13091697922952040237652398855281951745496785546756855157301003481130292290792"),
	bigint_t("20202875714649754365456438706218667574847291550262350301065084335018606838766"),
	bigint_t("492992264852455127449057665511791399647179651424042915864180906762763371715"),
	bigint_t("20133050518965930828443524230561515368266888311374696095290556899314550580922"),
	bigint_t("6385360226622661867718908595901562344465143474653216228142879027740329498038"),
	bigint_t("16189661955093768869863744989741157066417048119473389754290751422198516318482"),
	bigint_t("17390277422987664325022294423490418444622716492894117505168755032541741533377"),
	bigint_t("9554577648982986066685712539670385622581166377991875181419580034643019756647"),
	bigint_t("15704386641366927508004662856002161833359863394256443981705797781265688027074"),
	bigint_t("4442965131292787039170729599423359441993222498882237871701410552013270179809"),
	bigint_t("9992458950326372388903306854856846512849825831943926912936440732625017970733"),
	bigint_t("19181144614236132922958164173919618755815580517968093815750133496884405775603"),
	bigint_t("4641016376415487036150057977128816174611453009426646819376640332083288411061"),
	bigint_t("16696596087870869328072214030748372566368676652025714981169975969462125590025"),
	bigint_t("289755461885121629295392309430354226839484519042650122040089592611401377270"),
	bigint_t("17054710395420445502304216080928288827342394658387865697407531009149986259948"),
	bigint_t("10776482662882928745998797501650135426653877254664764045304025554514996800783"),
	bigint_t("7181672099082463768543492393064762214525014703114053444414241228021643766075"),
	bigint_t("13717658667492863589228163677378686435581564268139005968935996694855033792130"),
	bigint_t("13977036248582615191656636818672282874103060143929720229997901719203646618980"),
	bigint_t("9527329642633741365185089402655475658849265935000560290337531390660499324731"),
	bigint_t("3900118811851691763732250231706696813868067976919915967336759638332285945845"),
	bigint_t("18190235287487460653248526211086738871190393710713724404731953314544607724014"),
	bigint_t("13922486273933707845464236788932657492788147121053959600325814223990056224156"),
	bigint_t("2477224141869865421837475771721555267385017843443103476101374527722064199637"),
	bigint_t("12334613684659562440788630503153043093977045601469370045588301254814231848587"),
	bigint_t("1801704405247675172375542099369161347308119676867519972191701046901605939152"),
	bigint_t("9682376581580360121533987019350265025099687532291427069091020284081873505954"),
	bigint_t("16476544656218217828713579961365340965979747788876130431303926848616603963352"),
	bigint_t("18214979012132662846817702358686326262481947780626976530362214802296373116112"),
	bigint_t("7505252717634158601332448479040249807636108760342982908314615542100634702180"),
	bigint_t("20244416530053340394018658730926707970966932774944997166066316600068475856611"),
	bigint_t("11462970730131980349012857955472192686375049170899216850611944882658842403955"),
	bigint_t("15833589416680944965154792914165965350302019595208110200940861362249820136489"),
	bigint_t("3128611105025225256998039331695201966350915164968493295831922376771297707177"),
	bigint_t("2087375279244451546911575442863634058406888389109669942894662956862870202376"),
	bigint_t("8678233673330518711874986191665939912224859379065178052785688170035257476393"),
	bigint_t("7599171988032622230014236578487547016983766955945227388277429265087216336376"),
	bigint_t("21356378579260673408093679809396322770511359120990248771932615226446380042193"),
	bigint_t("16701754563724418242501123706373197435086677952433579060796094021531526737665"),
	bigint_t("21273069373124366551321250219045082446082227894396521753876952190387371806081"),
	bigint_t("18996098282443114495254006940912284439826000652180983712295191888771210572370"),
	bigint_t("1005690367878139850918944797586022946962013253640305495021702848361405218702"),
	bigint_t("6344251793838367607839775348589469685426524839305532620369286323010601589271"),
	bigint_t("17359385429441733269509840623839253470600370666099850858902369687803881284763"),
	bigint_t("806966391820755034564266020372585872141944546237588911201649451865410536784"),
	bigint_t("14643838818894421596071987699711998830367621953985271472821737195777795977182"),
	bigint_t("20977928953124614302914903478314998646110332311172925003395038802287464774395"),
	bigint_t("1392253163164325259101481671194870360048136778815178879986456125575276999611"),
	bigint_t("11867822419702644795741362527869162016053088761210837554713214818131178502869"),
	bigint_t("16736949602581315222743530120856089665097950810549747944927300176576401706290"),
	bigint_t("4857665716129516163271813419680583624840427804995291369101822590281998643489"),
	bigint_t("2607731647594825817774252333860723230195233108499522976148008109833363004203"),
	bigint_t("13991410474819751840188006555449609534423649948799722699285604151935008713929"),
	bigint_t("16793966242945633397183753124634526123542620055727622091689471541568429414836"),
	bigint_t("7758099221746226559967502107244072845185590922576951423580803881694179912470"),
	bigint_t("3645557311490522308720331600273611650198993547869738912415755584699140854086"),
	bigint_t("4439129326239892964656857786972655467329383546313393105912578285900136494840"),
	bigint_t("18177514617468996075552365411022990441585593628265048259719800314566211564292"),
	bigint_t("10308163919699812862707656679981352577266134176283451098732886984442747664641"),
	bigint_t("10610288780628896445609384440545799145708730444731640762445394744485535174334"),
	bigint_t("52437471116934306229176718264831557706182985109729034588889616968197220103"),
	bigint_t("18574555095662225916658635889491547192091540460932986426314961424742308169396"),
	bigint_t("17653649420739807163895437047820297987115998390204970815910991930219783522254"),
	bigint_t("16988512864589756817733927811052334073525122005376919689768595138785416457629"),
	bigint_t("12685202629861687452744568674726235467680852044618865108464634846888036084055"),
	bigint_t("16009863513646476800490498442450925773125591261566735591237396645239286128037"),
	bigint_t("15057606421401347445393373595071223289101753558541084482333056496148126030670"),
	bigint_t("18359948888086370112928437577801653455061125459092679427808188255588885313820"),
	bigint_t("381928092342008763463804739943164694916130308215484427201095423010837591117"),
	bigint_t("11461042658945179413757609516877691795711213176901074257632486431122581176603"),
	bigint_t("3558830745598906522971813371384361198629734644003412905102807672264107502911"),
	bigint_t("8468441490411212501982575759313995238002511720157390524382089923954517341827"),
	bigint_t("17701071785850676494049327209099814903358624773410736705051321779189965764739"),
	bigint_t("13945988189126214122626588241323048827108376209454276892977161369454912184432"),
	bigint_t("3129771523362096017810902763033255652722922035624625729299049742947495744655"),
	bigint_t("14337105988534144244756380569531346370422574732886248399727291486124035429247"),
	bigint_t("13176818679681058031275582033231458196334372994635781312712537690609511316076"),
	bigint_t("7149581709406877595329106301919219669475873265979952483638968072010616950259"),
	bigint_t("15110131811355569497876505947251292320073547307312203723670948013113675223995"),
	bigint_t("19911051925679410443561894850783389190276861614272836744195858326357647059698"),
	bigint_t("2129175247750746129249819022733452264446550812082190647067303661139649724622"),
	bigint_t("12901496640384284593719209686823930721643213913311728714437226474739309574391"),
	bigint_t("18481572591560940700430436309509769308566790738508941561584596921724061659451"),
	bigint_t("8339060346425983376228645966354540885424119347560050546761518321413663416797"),
	bigint_t("19254968442925401548300319051202355789791341360682737046215134604118987870090"),
	bigint_t("4787434405389913008283693974184625782704608315722629665519469061384676461698"),
	bigint_t("18657441804515438929487991390920188583814039833323897303035348343884973607304"),
	bigint_t("7888148829563497957344996172200212307955092695191318595706752056610423590576"),
	bigint_t("21784070287099047996522664479273436673731409527420357021176323356249129527932"),
	bigint_t("11787489920459901522586610328656965847960515397277484282923181014380348496397"),
	bigint_t("17598242660237692833933228368920955666126630456251056679950326353038545205007"),
	bigint_t("8369961726647487308510451026580408174977142313282888238426752908156870177788"),
	bigint_t("16007968409066302483990211662430697770447177729575104309519857879697766102642"),
	bigint_t("7784631375347091040374818629730119584369242620883834703638223055442711326439"),
	bigint_t("13639313256093830553171517345740094847426536812501821592648666236535281612870"),
	bigint_t("7237386988749150094765884634360757365015813848859817616779755685932403723208"),
	bigint_t("1805174290373765033446067791204925604348229302129062468443708217413607916149"),
	bigint_t("17841036375195584638761722760700988675865677656391483910222394027066187090714"),
	bigint_t("14688597292534995253198368985796452592575273786305270177242444905353714648260"),
	bigint_t("4303635574981164191375544026298238549980802074230728556914135602803378939018"),
	bigint_t("4762360887019934774548373834036905036916132133009446469990948220443348451243"),
	bigint_t("16596576569778204900595508452923123410598037460902260104192294680712988393826"),
	bigint_t("6950061647430958678225926805135128953489852948086450897592898949118942623765"),
	bigint_t("17450109461726280342028204564001156522140296237271540672640879327588615564762"),
	bigint_t("15620253561966538035573970143592698431774671878027519213935958364044069643996"),
	bigint_t("11273884550470411320131172957382334025435295061941823991655035050723600442983"),
	bigint_t("4800944624175647995094807563578352381439858391319314745155831738751951521513"),
	bigint_t("14792207006076823546791192235320190885154800423901118229485671270737655123769"),
	bigint_t("14685547412643310774046228488857734038914168961601600377918964274505754841081"),
	bigint_t("11562549102126952531896454737677494836925332485308338527312254117753082408695"),
	bigint_t("921579554002494186743838250423169450676470988691989174144762233930314429633"),
	bigint_t("20895436318692093248853267540593149819268975968765408549399482664684391805869"),
	bigint_t("10434598755648719160880385925651731142868064463420443622135471203241402549501"),
	bigint_t("16722970005037567596533956916775514928466256127213173656258068820303340861846"),
	bigint_t("4980629720184370054700630150245877651875699926120097398139874199522818822983"),
	bigint_t("10929554065119709325151802408928651022756984083824084002228641392607178814673"),
	bigint_t("21592540660630521107226828621197781814591640289437965868892651011216514970559"),
	bigint_t("5304630745274610137851745416320252873490351220060593117886115769595770349530"),
	bigint_t("13823177211959543636679348077494007027219993638908366838452515760723132637086"),
	bigint_t("8328709654613530865489170757538953042231522656933618684486573687421538803506"),
	bigint_t("2920107970702978498312450540668022917612971169301352792446803362936554215425"),
	bigint_t("18300223921236474321928495259233992394435202620716465786164819395988049305978"),
	bigint_t("925691893041359315556657496081753798633064692832926021731808892981622160208"),
	bigint_t("1349781668348284893671650493748613207680309108481173469485115372114328339986"),
	bigint_t("4546503237812876453130880634866446919553188775567282907992169974311535954391"),
	bigint_t("3023782556583052410699333291402711050029184769785951214903401355220344914679"),
	bigint_t("14478115738460051765013281045037704848205092625953109976920529262379379826501"),
	bigint_t("10145297342548946743630743794160253934312474450886456676285881995516493024707"),
	bigint_t("5617213056443178292071217725685736759426613777033756475833338918474712826966"),
	bigint_t("18346326699996683865574627674547724634867376477654935337984340943822300441036"),
	bigint_t("12400362670083997202920176500582460053213731105072306395488623670505303272097"),
	bigint_t("20297177143624659781004712007760342851211002003606210704690035979853696141724"),
	bigint_t("3853169347456031892538801252304691301380707733267395485809123504076549973406"),
	bigint_t("4002365124825300034028868738704737142437211467315807490372889798554565879702"),
	bigint_t("2358269495764309540879578475376371736403043623397016336938879376961631365446"),
	bigint_t("15229796349187403359977698344867567489923030569776242465408973593515231667524"),
	bigint_t("3299482889683463917296138216234632176997689296054718714220791301634539751579"),
	bigint_t("8981318196125954901838352745879952062814782858662296832379403621425543464719"),
	bigint_t("9214636388943583315614939129002316590727502712381589994676023783157459960937"),
	bigint_t("11077767429080867462869521260141436043440148510412042964531771485591119029317"),
	bigint_t("16685179630174301049818010031284665100577888157519304035662497733684666447189"),
	bigint_t("16962938633085895014306988226745063415804904648624714591263481988863146846157"),
	bigint_t("4474504145206351535782285228239373518447939833152667501854872651392531560618"),
	bigint_t("9360826242750819005504307474183538555056288469709255568787913150394570300650"),
	bigint_t("9334297972928716802823384955998311646268891068359740615882251544438168451937"),
	bigint_t("7027510586032164859031155838813573250152507237122199505776301631701181029342"),
	bigint_t("21831178635755793310997521796841547075433684510128457625556917154063659853321"),
	bigint_t("9821211841457309432473022011350422916741779159601613441354331868674446743019"),
	bigint_t("16143702089388984615117765979331429694530544141187360325873324508330226172042"),
	bigint_t("17206376155359149945255627266759260691267884731249460347154695156251301976159"),
	bigint_t("21154668868570399213508345571667640975566670939189174039069103914464374498150"),
	bigint_t("19376076620364286185332587430737334872869516489850724516145978933535948323426"),
	bigint_t("17540132852531208124174926600464241804101429010452546856279348586953259275784"),
	bigint_t("14769919043149806520739494256299659862952839058243842871612901499790156094124"),
	bigint_t("4579871415985025465150026613485924173478923523129172905142820900585057522038"),
	bigint_t("5838251506599259968133469575341020257967694885886937829805853998086795315375"),
	bigint_t("13860358505967938312107396641736883868884520711883237283588473335692630600454"),
	bigint_t("6132027828377982500811383509238216089945976223443020253835496357227280885732"),
	bigint_t("4556591617851282363254622559390919153872009058600844299587861468063202921048"),
	bigint_t("2770664380491811353856748059747125733131988329847169718007157717131823941072"),
	bigint_t("11857199329721640724009407775980887327492400185928675024367032051452055267184"),
	bigint_t("16135725474191630664493403771960784845210867199504917062959700745670115797116"),
	bigint_t("21479137430485387946351515233844880951212233795417761825343317219975686267660"),
	bigint_t("10024965946123508316007664454500505088928480189036634881477771865210020420938"),
	bigint_t("8947697529973303892583455363584227310582283196393354532350725136746564313204"),
	bigint_t("6419099223180730305712956956676719219496102133448397625898181420312058739582"),
	bigint_t("6718555696831262139992535377621019816491050365354537729338120136611627267925"),
	bigint_t("232869830359083579942029951459273056285233053170897549934469415906553648643"),
	bigint_t("20496593747431194806711867368124611750050553572822217947347525416111065232644"),
	bigint_t("5133550392731602064431943258183915477702288756255885592886116735708658495090"),
	bigint_t("21663087038777308103541855661467022595282266325676148592978509815983487171518"),
	bigint_t("11310883876588193341393540407649236571499786126947599780608443796842652783418"),
	bigint_t("8556380798970194381872977139532406932389239370443062441395829234810789984266"),
	bigint_t("12107429541712586699738829571046141306893103432412891082890457433417209359685"),
	bigint_t("16644521730844267690002363109054255090569952644638413083721883266713794048844"),
	bigint_t("8269359170621593168071111762610715693952302610195644361990116180541354686329")
};
