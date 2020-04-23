#!/usr/bin/perl
#coder: kodo no kami
#modelo router: sagemcom F\@ST™ 2704N 
#descrição: exibe quem tiver conectado no wifi, detector de intrusão

use WWW::Mechanize;
use Term::ANSIColor;

open(KARQ_CONF,"<config.conf");

my $arpspoofing_log = 0;

while($linconf = readline(KARQ_CONF)){
	if($linconf !~ /^#/){
		@arr_conf = split("=",$linconf);
		
		if($arr_conf[0] eq "host"){
			chomp($arr_conf[1]);
			 $host = $arr_conf[1];
		}
		elsif($arr_conf[0] eq "usuario"){
			chomp($arr_conf[1]);
			 $usuario = $arr_conf[1];
		}
		elsif($arr_conf[0] eq "password"){
			chomp($arr_conf[1]);
			 $password = $arr_conf[1];
		}
		elsif($arr_conf[0] eq "macs"){
			chomp($arr_conf[1]);
			 $allow = $arr_conf[1];
		}
		elsif($arr_conf[0] eq "new"){
			chomp($arr_conf[1]);
			 $new = $arr_conf[1];
		}
		elsif($arr_conf[0] eq "tempo"){
			chomp($arr_conf[1]);
			 $tempo = $arr_conf[1];
		}
		elsif($arr_conf[0] eq "msg"){
			chomp($arr_conf[1]);
			 $msg = $arr_conf[1];
		}
		elsif($arr_conf[0] eq "ids"){
			chomp($arr_conf[1]);
			 $ids = $arr_conf[1];
		}
		elsif($arr_conf[0] eq "arpspoof"){
			chomp($arr_conf[1]);
			 $arpspoof = $arr_conf[1];
		}
		elsif($arr_conf[0] eq "macroute"){
			chomp($arr_conf[1]);
			 $macroute = $arr_conf[1];
		}
		elsif($arr_conf[0] eq "log"){
			chomp($arr_conf[1]);
			 $log = $arr_conf[1];
		}
	}
}

close(KARQ_CONF);

my $kreq = new WWW::Mechanize;

my (%macs, @macs_old);

while(1){
	system("clear");
	print color('bold blue');
	print "[--- Wireless IDS Sagemcom ---]\n".
		  "         F\@ST™ 2704N\n\n";
	print color('bold yellow');
	print "coder: kodo no kami <discord:kodo#0010>\n\n";

	$kreq->get("http://$usuario:$password\@$host/wlstationlist.cmd");

	my @klogado = $kreq->content =~ /<tr> <td><p align=center>.*?\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}.*?<\/tr>/sgmi;

	@tempo = localtime();

	#arpsoofing
	if($arpspoof == 1){
		if($^O eq "linux"){
			open(KGATEWAY,"ip route show default |");
			while($lincmd = readline(KGATEWAY)){
				@gateway = $lincmd  =~ /default via (\d+\.\d+\.\d+\.\d+).*?dev (.*?)\ /s;	
							
				if(length($gateway[0]) > 1){
					open(KSPOOF,"arp -n |");
					while($linspoof = readline(KSPOOF)){
						if($linspoof =~ /$gateway[0]/){
							@mspo = $linspoof =~ /(\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2})/i;

							if($mspo[0] ne $macroute){
								print color('bold red');
								print("alerta: ataque de arpspoof detectado em $mspo[0]\n\n");
								
								if($arpspoofing_log == 0){
									open(KARQ_LOG,">>" . $log);
									print KARQ_LOG "$tempo[3]/$tempo[4]/" . ($tempo[5] + 1900) ." $tempo[2]:$tempo[1] ataque de arpspoofing para $mspo[0]\n";
									$arpspoofing_log = 1;
									close(KARQ_LOG);
								}
							}
						}
					}
					close(KSPOOF);
				}
				
			}
			close(KGATEWAY);
		}
	}
	else{
		$arpspoofing_log = 0;
	}

	print color('bold white');
	print "MAC - ASSOCIADO/AUTORIZADO ~ SSID (ID)\n\n";

	#pegar os mac no arquivo
	open(KARQ_ALLOW,"<" . $allow);
	@arr_allow = <KARQ_ALLOW>;
	close(KARQ_ALLOW);

	$macs = {};
	
	foreach $a(@arr_allow){
		@a_sepa = split(",",$a);
		chomp($a_sepa[1]);
		$macs->{$a_sepa[0]} = $a_sepa[1];
	}
	@arr_allow = ();

	$new_detect = 0;
	foreach my $kl(@klogado){
		my @param = $kl =~ /p align=center>(.*?)</gsim;
		
		$param[0] =~ s/^\ +//g;
		$param[0] =~ s/\ +$//g;
		$param[0] =~ s/&nbsp//g;
		$param[1] =~ s/^\ +//g;
		$param[1] =~ s/\ +$//g;
		$param[2] =~ s/^\ +//g;
		$param[2] =~ s/\ +$//g;
		$param[3] =~ s/^\ +//g;
		$param[3] =~ s/\ +$//g;
		$param[3] =~ s/&nbsp//g;
		
		chomp($param[0]);
		chomp($param[1]);
		chomp($param[2]);
		chomp($param[3]);
		
		#detectar novos macs
		open(KARQ_NEW,"<" . $new);
		@arr_new = <KARQ_NEW>;
		close(KARQ_NEW);
		$new_detect = 0;
		foreach $a(@arr_new){
			chomp($a);
			if($a eq $param[0]){
				$new_detect = 1;
			}
		}
		if($ids == 1){
			if($new_detect == 0){
				if($^O eq "linux" ){
					system("zenity --warning --text '$msg $param[0]' &");
				}
				else{
					system("msg * '$msg $param[0]'");
				}
				open(KARQ_NEW,">>" . $new);
				print KARQ_NEW $param[0] . "\n";
				
				open(KARQ_LOG,">>" . $log);
				print KARQ_LOG "$tempo[3]/$tempo[4]/" . ($tempo[5] + 1900) ." $tempo[2]:$tempo[1] primeira conexao $param[0]\n";
				close(KARQ_LOG);
				close(KARQ_NEW);
			}
		}
		@arr_new = ();
		
		if($macs->{$param[0]}){		
			if($param[1] =~ /nbsp/){
				print color('magenta');
			}
			else{
				print color('bold green');
			}
			print "$param[0] - ";
			if($param[1] =~ /nbsp/){
				print "outra rede ";
			}
			else{
				print "$param[1]/$param[2] ";
			}
			print "~ $param[3] (" . $macs->{$param[0]} . ")";
			print color('blue');
		}
		else{
			print color('bold red');
			print "$param[0] - ";
			if($param[1] =~ /nbsp/){
				print "outra rede ";
			}
			else{
				print "$param[1]/$param[2] ";
			}
			print "~ $param[3] (INVASOR)";
			print color('white');
		}
		print "\n";

		#log conexao
		$mac_i = 0;
		foreach $mac_o(@macs_old){
			if($mac_o eq $param[0]){
				$mac_i = 1;
			}
		}

		if($mac_i == 0){
			open(KARQ_LOG,">>" . $log);
			print KARQ_LOG "$tempo[3]/$tempo[4]/" . ($tempo[5] + 1900) ." $tempo[2]:$tempo[1] conexao $param[0] ($macs->{$param[0]}) \n";	
			close(KARQ_LOG)
		}
		push(@macs_temp,$param[0]);
	}
	
	undef @macs_old;
	@macs_old = @macs_temp;
	undef @macs_temp;
	
	sleep($tempo);
}
