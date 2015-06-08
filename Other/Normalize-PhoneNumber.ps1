# Нормализация телефонных номеров
# к полному 13-значному международному формату +XXYYYZZZZZZZ
# либо к 10-значному междугороднему формату YYYZZZZZZZ

function Normalize-PhoneNumber {
	[OutputType([System.String])]
	param(
		[Parameter(ValueFromPipeline=$true)]
		[ValidateNotNullOrEmpty()]
		[String]
		$PhoneNumber,
		
		[ValidateSet("Normalize","International","Intercity","Local","CustomLength")]
		[ValidateNotNullOrEmpty()]
		[string]
		$OutputFormatType="Normalize",
		
		[string]
		$CountryPrefix="+38",
		
		[int]
		$NumberLength=14
		
	)
	begin { 
		function TrimNumber( [string]$inp, [int]$len ) { 
			if ($inp.Length -gt $len) { 
				$out = $inp.Substring($inp.Length-$len) 
			} else {$out = $inp}
			return $out
		}
	
		$AllowedChars = ("0","1","2","3","4","5","6","7","8","9","+") 
	}
	process { 
		$n = -join $([char[]]$PhoneNumber | ?{$_ -in $AllowedChars})
		switch ($OutputFormatType) {
			"International" { # международный формат - обрезает все до первого "+", затем оставляет последние 13 символов номера
							  # если номер короче 13, то
							  # 	если номер 10 символов - добавляет в начало $CountryPrefix
							  #		иначе выдает ошибку
				if  ($n.IndexOf("+") -ne -1) {
					$n = $n.Substring($n.IndexOf("+"))
					if ($n.Length -lt 13 ) { 
						Write-Error "Wrong phone number: $PhoneNumber"
						$n = $PhoneNumber
					} elseif ($n.Length -gt 13 )  {
						$n = $n.Substring(0,13)
					}
				} elseif ( $n.Length -eq 10 ) {
					$n = $CountryPrefix + $n										
				} else {
					Write-Error "Wrong phone number: $PhoneNumber"
					$n = $PhoneNumber
				}				
			}
			"Intercity"		{ # меджугородний формат - оставляет последние 10 цифр номера (или меньше - если номер короче 10 знаков)
				$n = TrimNumber $n 10
			}
			"Local"			{ # городской флрмат - оставляет последние 7 цифр номера (или меньше - если номер короче 7 знаков)
				$n = TrimNumber $n 7
			}
			"CustomLength"	{ # кастомная длина номера - оставляет последние $NumberLength символов номера 
				$n = TrimNumber $n $NumberLength
			}
		}
		return $n
	}
}


