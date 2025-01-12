#include "ws.h"

static void onopen(ws_client *cli) {
  (void)cli;
  printf("connected\n");
  char *s = malloc(12498);
  if (!s) return;
  memset(s, 0, 12498);
  strcat(s, "Iran Was 'Defeated Very Badly' in Syria, a Top General Admits\n\n");
  strcat(s, "For weeks, Iranian officials have downplayed the fall of their ally in Syria.\n");
  strcat(s, "But an important general has offered a remarkably candid view of the blow\n");
  strcat(s, "to Iran, and its military's prospects.\n\n");
  strcat(s, "Iran's top ranking general in Syria has contradicted the official line taken\n");
  strcat(s, "by Iran's leaders on the sudden downfall of their ally Bashar al-Assad,\n");
  strcat(s, "saying in a remarkably candid speech last week that Iran had suffered a\n");
  strcat(s, "major defeat but would still try to operate in the country.\n\n");
  strcat(s, "An audio recording of the speech, given last week by Brig. Gen. Behrouz\n");
  strcat(s, "Esbati at a mosque in Tehran, surfaced publicly on Monday in Iranian media,\n");
  strcat(s, "and was a stark contrast to the remarks of Iran's president, foreign minister\n");
  strcat(s, "and other top leaders. They have for weeks downplayed the magnitude of\n");
  strcat(s, "Iran's strategic loss in Syria last month, when rebels swept Mr. al-Assad\n");
  strcat(s, "out of power, and said Iran would respect any political outcome decided\n");
  strcat(s, "by Syria's people.\n\n");
  strcat(s, "\"I don't consider losing Syria something to be proud of,\" said General\n");
  strcat(s, "Esbati according to the audio recording of his speech, which Abdi Media,\n");
  strcat(s, "a Geneva-based news site focused on Iran, published on Monday. \"We were\n");
  strcat(s, "defeated, and defeated very badly, we took a very big blow and it's been\n");
  strcat(s, "very difficult.\"\n\n");
  strcat(s, "General Esbati revealed that Iran's relations with Mr. al-Assad had been\n");
  strcat(s, "strained for months leading to his ouster, saying that the Syrian leader\n");
  strcat(s, "had denied multiple requests for Iranian-backed militias to open a front\n");
  strcat(s, "against Israel from Syria, in the aftermath of the Hamas-led attack of\n");
  strcat(s, "Oct. 7, 2023.\n\n");
  strcat(s, "Iran had presented Mr. al-Assad with comprehensive military plans on how\n");
  strcat(s, "it could use Iran's military resources in Syria to attack Israel, he said.\n\n");
  strcat(s, "The general also accused Russia, considered a top ally, of misleading Iran\n");
  strcat(s, "by telling it that Russian jets were bombing Syrian rebels when they were\n");
  strcat(s, "actually dropping bombs on open fields. He also said that in the past year,\n");
  strcat(s, "as Israel struck Iranian targets in Syria, Russia had \"turned off radars,\"\n");
  strcat(s, "in effect facilitating these attacks.\n\n");
  strcat(s, "For over a decade, Iran backed Mr. al-Assad by sending commanders and troops\n");
  strcat(s, "to help it fight against opposition rebels and the Islamic State terrorist group.\n\n");
  strcat(s, "Under Mr. al-Assad, Syria was Iran's regional command center from which\n");
  strcat(s, "it supplied weapons and money to its network of regional militias, including\n");
  strcat(s, "Hezbollah in Lebanon and Palestinian militants in the West Bank. Iran also\n");
  strcat(s, "controlled airports, warehouses and operated missile and drone manufacturing\n");
  strcat(s, "bases in Syria.\n\n");
  strcat(s, "The rebel coalition has now taken over much of Syria and is trying to form\n");
  strcat(s, "a government. General Esbati said in his speech that Iran would look for\n");
  strcat(s, "ways to recruit insurgents in whatever shape the new Syria takes.\n\n");
  strcat(s, "\"We can activate all the networks we have worked with over the years,\"\n");
  strcat(s, "he said. \"We can activate the social layers that our guys lived among for\n");
  strcat(s, "years; we can be active in social media and we can form resistance cells.\"\n\n");
  strcat(s, "He added, \"Now we can operate there as we do in other international arenas,\n");
  strcat(s, "and we have already started.\"\n\n");
  strcat(s, "The general's comments have stunned Iranians, for both their unfiltered\n");
  strcat(s, "content and the speaker's stature. He is a top commander of Iran's Armed\n");
  strcat(s, "Forces, the umbrella that includes the military and the Revolutionary\n");
  strcat(s, "Guards Corps, with a record of prominent roles including commander in\n");
  strcat(s, "chief of the Armed Forces' cyber division.\n\n");
  strcat(s, "In Syria, he supervised Iran's military operations and coordinated closely\n");
  strcat(s, "with Syrian ministers and defense officials and with Russian generals —\n");
  strcat(s, "outranking even the commander in chief of the Quds Forces, Gen. Ismail\n");
  strcat(s, "Ghaani, who oversees the network of regional militias backed by Iran.\n\n");
  strcat(s, "Mehdi Rahmati, a prominent analyst in Tehran and expert on Syria, said in\n");
  strcat(s, "a telephone interview that General Esbati's speech was significant because\n");
  strcat(s, "it showed that some senior officials were parting from government propaganda\n");
  strcat(s, "and leveling with the public.\n\n");
  strcat(s, "\"Everyone is talking about the speech in meetings and wondering why he said\n");
  strcat(s, "these things, especially at a public forum,\" Mr. Rahmati said. \"He very\n");
  strcat(s, "clearly laid out what happened to Iran and where it stands now. In a way\n");
  strcat(s, "it can be a warning for domestic politics.\"\n\n");
  strcat(s, "General Esbati said the fall of the Assad regime was inevitable given the\n");
  strcat(s, "rampant corruption, political oppression and economic hardship that people\n");
  strcat(s, "faced, from lack of power to fuel to livable incomes. He said Mr. al-Assad\n");
  strcat(s, "had ignored the warnings to reform. Mr. Rahmati, the analyst, said that the\n");
  strcat(s, "comparison to Iran's current situation was hard to miss.\n\n");
  strcat(s, "Despite the general's assertions about activating networks, it remains\n");
  strcat(s, "unclear what Iran can realistically do in Syria, given the public and\n");
  strcat(s, "political opposition it has faced in the country and the challenges of\n");
  strcat(s, "land and air access. Israel has warned that it would decimate any Iranian\n");
  strcat(s, "efforts it detects on the ground in Syria.\n\n");
  strcat(s, "And while Iran has the experience of operating in Iraq after the U.S.\n");
  strcat(s, "invasion in 2003 — including sowing unrest — the geography and political\n");
  strcat(s, "landscape of Syria differ greatly, presenting more challenges.\n\n");
  strcat(s, "An Iranian member of the Revolutionary Guards who spent years in Iraq as\n");
  strcat(s, "a military strategist alongside senior commanders said in a telephone\n");
  strcat(s, "interview that General Esbati's comments about Iran recruiting insurgents\n");
  strcat(s, "might be more aspirational than practical at this stage. He said that\n");
  strcat(s, "while General Esbati had admitted a serious defeat, he had also sought\n");
  strcat(s, "to boost morale and pacify conservatives demanding that Iran act more forcefully.\n\n");
  strcat(s, "The Guards official, who asked that his name not be used because he was\n");
  strcat(s, "discussing sensitive issues, said Iran's policy had not yet been finalized\n");
  strcat(s, "but that a consensus had emerged in meetings he had attended where strategy\n");
  strcat(s, "was debated. He said Iran would benefit if Syria descended into chaos\n");
  strcat(s, "because Iran knew how to thrive and secure its interests in a turbulent\n");
  strcat(s, "landscape.\n\n");
  strcat(s, "In Iran, the Revolutionary Guards have the authority to set regional policy\n");
  strcat(s, "and overrule the foreign ministry.\n\n");
  strcat(s, "Supreme Leader Ayatollah Ali Khamenei, who has the last word on key state\n");
  strcat(s, "matters, has said in at least two speeches since Mr. al-Assad's fall that\n");
  strcat(s, "resistance was not dead in Syria, adding that Syria's youth would reclaim\n");
  strcat(s, "their country from the ruling rebels, whom he called stooges of Israel and\n");
  strcat(s, "the United States. President Masoud Pezeshkian and Foreign Minister Abbas\n");
  strcat(s, "Araghchi have been more conciliatory, saying they favor stability in Syria\n");
  strcat(s, "and diplomatic ties with the new government.\n\n");
  strcat(s, "The tensions surrounding these competing views on Syria preoccupied officials\n");
  strcat(s, "enough that they embarked on a campaign of damage control with the public\n");
  strcat(s, "last week. Senior military commanders and pundits close to the government\n");
  strcat(s, "gave speeches and held question-and-answer sessions with audiences in mosques\n");
  strcat(s, "and community centers in several cities.\n\n");
  strcat(s, "General Esbati's speech, on Dec. 31 at the Valiasr mosque in central Tehran,\n");
  strcat(s, "addressed rank and file of the military and constituents of the mosque,\n");
  strcat(s, "according to a public notice of the event, titled, \"Answering questions\n");
  strcat(s, "about Syria's collapse.\"\n\n");
  strcat(s, "The session started with General Esbati telling the crowd he left Syria\n");
  strcat(s, "on the last military plane to Tehran the night before Damascus fell to\n");
  strcat(s, "rebels. It ended with him answering questions from audience members. He\n");
  strcat(s, "offered his most sobering assessment on Iran's military capability in\n");
  strcat(s, "fighting Israel and the United States.\n\n");
  strcat(s, "Asked whether Iran would retaliate for Israel killing Hezbollah's longtime\n");
  strcat(s, "leader, Hassan Nasrallah, he replied that Iran already did, referring to\n");
  strcat(s, "a missile barrage last fall. Asked whether Iran planned to carry out a\n");
  strcat(s, "third round of direct strikes on Israel, he said that \"the situation\"\n");
  strcat(s, "couldn't realistically handle another attack on Israel right now.\n\n");
  strcat(s, "Asked why Iran would not fire missiles at U.S. military bases in the region,\n");
  strcat(s, "he said that would invite bigger retaliatory attacks on Iran and its allies\n");
  strcat(s, "by the United States, adding that Iran's regular missiles — not its advanced\n");
  strcat(s, "ones — could not penetrate advanced U.S. defense systems.\n\n");
  strcat(s, "Despite those assessments, General Ebati said that he wanted to assure\n");
  strcat(s, "everyone not to worry: Iran and its allies, he said, still had the upper\n");
  strcat(s, "hand on the ground in the region.\n\n");
  strcat(s, "Syria's Main Airport Handles First International Flights Since Fall of\n");
  strcat(s, "al-Assad\n\n");
  strcat(s, "The country's new leaders are pushing to restore a sense of normalcy.\n");
  strcat(s, "But Syria remains under a host of international sanctions imposed during\n");
  strcat(s, "the Assad regime.\n\n");
  strcat(s, "Syria's main airport handled its first international flights on Tuesday\n");
  strcat(s, "since the fall of the government of former President Bashar al-Assad\n");
  strcat(s, "last month, as the new leaders press to reassert a semblance of normalcy\n");
  strcat(s, "in the war-weary country.\n\n");
  strcat(s, "One Qatar Airways plane landed following a direct flight from Doha to the\n");
  strcat(s, "Syrian capital, Damascus. Jordan's Civil Aviation Authority announced that\n");
  strcat(s, "it had also sent an initial flight to Damascus on Tuesday morning as a\n");
  strcat(s, "\"message of support\" to its northern neighbor, the first trip there by\n");
  strcat(s, "its national carrier in 13 years.\n\n");
  strcat(s, "Another flight affiliated with Syria's national carrier took off on Tuesday\n");
  strcat(s, "for the United Arab Emirates carrying 145 passengers, according to Syrian\n");
  strcat(s, "state media. Video shared by Syrian media showed people on board waving\n");
  strcat(s, "Syrian flags and singing nationalist songs.\n\n");
  strcat(s, "Syria's new Islamist leaders have pledged to convene a committee to draft\n");
  strcat(s, "an inclusive constitution for the country. They have urged civil servants\n");
  strcat(s, "to return to work to get the machinery of government up and running, and\n");
  strcat(s, "they insist that Syria no longer poses any threat to its neighbors.\n\n");
  strcat(s, "But the country remains under a host of international sanctions imposed\n");
  strcat(s, "during the regime of Mr. al-Assad. And the new interim government is run\n");
  strcat(s, "by Hayat Tahrir al-Sham, which many countries have blacklisted as a terrorist\n");
  strcat(s, "group for its erstwhile ties to Al Qaeda, although it broke with the group\n");
  strcat(s, "several years ago.\n\n");
  strcat(s, "Western leaders have responded to the new administration with a mix of\n");
  strcat(s, "optimism and caution, fearing that Hayat Tahrir al-Sham could impose Islamist\n");
  strcat(s, "rule on the country or generate a new wave of domestic turmoil. They have\n");
  strcat(s, "called for an inclusive political transition.\n\n");
  strcat(s, "\"Europe will support, but Europe will not be a patron of new Islamist\n");
  strcat(s, "structures,\" said Annalena Baerbock, Germany's foreign minister, during\n");
  strcat(s, "a visit to Damascus last week.\n\n");
  strcat(s, "The sanctions are one of the greatest obstacles for Syria's new administration\n");
  strcat(s, "as it tries to chart a path forward. As soon as Mr. al-Assad fled the country\n");
  strcat(s, "in December, one of the first requests of Ahmed al-Shara, the leader of the\n");
  strcat(s, "rebel coalition that overthrew the government, was for the United States\n");
  strcat(s, "and others to begin easing restrictions.\n\n");
  strcat(s, "On Monday, the Biden administration lifted some restrictions on humanitarian\n");
  strcat(s, "aid to Syria. Still, it kept strict sanctions in place, a reflection of\n");
  strcat(s, "how Western governments are carefully calibrating their approach to the\n");
  strcat(s, "new leaders.\n\n");
  strcat(s, "Asaad Hassan al-Shibani, Syria's new foreign minister, welcomed the Biden\n");
  strcat(s, "administration's decision to loosen the restrictions. Mr. al-Shibani and\n");
  strcat(s, "other newly minted Syrian officials have been on a regional tour to soothe\n");
  strcat(s, "Arab states that have been wary of Hayat Tahrir al-Sham's rise, including\n");
  strcat(s, "the United Arab Emirates.\n\n");
  strcat(s, "At a news conference in Jordan on Tuesday after a meeting with Ayman Safadi,\n");
  strcat(s, "the Jordanian foreign minister, he called for the remaining sanctions to\n");
  strcat(s, "be lifted immediately, arguing that Mr. al-Assad's downfall had removed\n");
  strcat(s, "any reason to keep them in place.\n\n");
  strcat(s, "\"Those economic sanctions are now being wielded against the Syrian people,\n");
  strcat(s, "even as the reason they were imposed is no more,\" Mr. al-Shibani said.\n");
  strcat(s, "\"They should have been canceled as soon as the previous regime was toppled.\"\n\n");
  strcat(s, "Syria and Jordan agreed to establish a joint commission to tackle security\n");
  strcat(s, "affairs along their shared border, Mr. Safadi said. Jordan has long expressed\n");
  strcat(s, "concerns about the smuggling of weapons and drugs from Syrian territory,\n");
  strcat(s, "particularly captagon, an illegal stimulant that was illicitly trafficked\n");
  strcat(s, "by close associates of Mr. al-Assad.\n\n");
  strcat(s, "Mr. al-Shibani pledged that the new Syrian government would end captagon\n");
  strcat(s, "smuggling, which analysts say put immense profits into the coffers of senior\n");
  strcat(s, "officials in Mr. al-Assad's government.\n\n");
  strcat(s, "The threat of smuggling \"shall not return and we are ready to cooperate\n");
  strcat(s, "intensively on this matter,\" Mr. al-Shibani said.");
  printf("size = %ld\n", strlen(s));
  ws_send(cli, s);
  free(s);
}

static void onclose(ws_client *cli) {
  (void)cli;
  printf("disconected\n");
}

static int check_route(ws_client *cli, const char *path) {
  (void)cli;
  if (strcmp(path, "/stream") == 0) return 1;
  return 0;
}

static void ondata(ws_client *cli, int opcode, const char *data, size_t len) {
  if (opcode == TEXT) {
    if (len < BUFFER_SIZE)
      printf("recv (%ld): %s\n", len, data);
    else
      printf("recv (%ld)\n", len);
  } else {
    printf("recv (%ld)\n", len);
  }
  const char *resp = "s[\"good job\"]";
  ws_send(cli, (char *)resp);
}

static void onperodic(ws_server *srv) {
  ws_send_all(srv, "3");
}

int main (int argc, char **argv)
{
  const char *port = "8088";
  if (argc > 1) {
    port = argv[1];
  }
  ws_server *server = ws_event_create_server (port);
  if (!server) return -1;
  server->events.onopen = onopen;
  server->events.onclose = onclose;
  server->events.onmessage = ondata;
  server->events.onperodic = onperodic;
  server->events.is_route = check_route;
  ws_event_listen (server, 0);
  ws_event_dispose (server);
  return 0;
}
