# trule
Next generation host vulnerability scanning based on version matching rule base

We define the following rules for version based vulnerability detection

<Vulns>
	<Vulnerability added="2004-12-22" id="mysql-bug-report-symlink" modified="2013-08-22" published="2004-05-04" version="2.0">
		<name>MySQL Bug Report Symlink Vulnerability</name>
		<severity>2</severity>
		<cvss>(AV:L/AC:L/Au:N/C:N/I:P/A:N)</cvss>
		<Tags>
			<tag>Database</tag>
			<tag>Oracle</tag>
			<tag>Oracle MySQL</tag>
		</Tags>
		<AlternateIds>
			<id name="BID">9976</id>
			<id name="CIAC">P-018</id>
			<id name="CVE">CVE-2004-0381</id>
			<id name="DEBIAN">DSA-483</id>
			<id name="MANDRAKE">MDKSA-2004:034</id>
			<id name="OVAL">OVAL11557</id>
			<id name="REDHAT">RHSA-2004:569</id>
			<id name="REDHAT">RHSA-2004:597</id>
			<id name="XF">15617</id>
		</AlternateIds>
		<Description>
			<p>
mysqlbug in MySQL allows local users to overwrite arbitrary files via a symlink attack on the failed-mysql-bugreport temporary file.
			</p>
		</Description>
		<Check id="mysql-bug-report-symlink" scope="endpoint">
			<NetworkService type="MySQL">
				<Product name="MySQL" vendor="Oracle">
					<version>
						<range>
							<low>3.20.26</low>
							<high>3.23.59</high>
						</range>
					</version>
					<version>
						<range>
							<low>4.0.0</low>
							<high>4.0.19</high>
						</range>
					</version>
				</Product>
			</NetworkService>
		</Check>
		<Solutions>
			<summary>升級到最新版本的 Oracle MySQL</summary>
			<workaround>
				<p>
下載並套用更新:
					<a href="http://dev.mysql.com/downloads/mysql">http://dev.mysql.com/downloads/mysql</a>
				</p>
			</workaround>
		</Solutions>
		<cnnvd>CNNVD-200405-031</cnnvd>
	</Vulnerability>
	<Vulnerability added="2004-11-01" id="mysql-com-change-user-bof" modified="2013-08-22" published="2002-12-23" version="2.0">
		<name>MySQL COM_CHANGE_USER Buffer Overflow</name>
		<severity>8</severity>
		<cvss>(AV:N/AC:L/Au:N/C:P/I:P/A:P)</cvss>
		<Tags>
			<tag>Database</tag>
			<tag>Oracle</tag>
			<tag>Oracle MySQL</tag>
			<tag>Remote Execution</tag>
		</Tags>
		<AlternateIds>
			<id name="BID">6375</id>
			<id name="CONECTIVA">CLSA-2002:555</id>
			<id name="CVE">CVE-2002-1375</id>
			<id name="DEBIAN">DSA-212</id>
			<id name="MANDRAKE">MDKSA-2002:087</id>
			<id name="REDHAT">RHSA-2002:288</id>
			<id name="REDHAT">RHSA-2002:289</id>
			<id name="REDHAT">RHSA-2003:166</id>
			<id name="SUSE">SUSE-SA:2003:003</id>
			<id name="XF">10848</id>
		</AlternateIds>
		<Description>
			<p>
The COM_CHANGE_USER command in MySQL 3.x before 3.23.54, and 4.x to 4.0.6, allows remote attackers to execute arbitrary code via a long response.
			</p>
		</Description>
		<Check id="mysql-com-change-user-bof" scope="endpoint">
			<NetworkService type="MySQL">
				<Product name="MySQL" vendor="Oracle">
					<version>
						<range>
							<high>3.23.54</high>
						</range>
					</version>
				</Product>
			</NetworkService>
		</Check>
		<Solutions>
			<summary>升級到最新版本的 Oracle MySQL</summary>
			<workaround>
				<p>
下載並套用更新:
					<a href="http://dev.mysql.com/downloads/mysql">http://dev.mysql.com/downloads/mysql</a>
				</p>
			</workaround>
		</Solutions>
		<cnnvd>CNNVD-200212-064</cnnvd>
	</Vulnerability>
</Vulns>
