<?PHP

  class ARP_Frame implements Ethernet_Protocol {
    const PROTOCOL_NUMBER = 0x0806;
    
    const HARDWARE_ETHERNET = 0x0001;
    
    const OPCODE_REQUEST = 0x01;
    const OPCODE_REPLY = 0x02;
    
    private static $arpTable = array ();
    
    private $arpHardware = 0x0000;
    private $arpProtocol = 0x0000;
    private $arpOpcode = 0x00;
    
    private $sourceHardwareAddress = null;
    private $sourceProtocolAddress = null;
    private $targetHardwareAddress = null;
    private $targetProtocolAddress = null;
    
    // {{{ parse
    /**
     * Try to parse arp-data into this object
     * 
     * @param string $Data
     * 
     * @access public
     * @return bool
     **/
    public function parse ($Data) {
      // Check the length of data
      if (($Length = strlen ($Data)) < 8) {
        trigger_error ('ARP-Frame too short');
        
        return false;
      }
      
      // Parse static ARP-Data
      $arpHardware = (ord ($Data [0]) << 8) | ord ($Data [1]);
      $arpProtocol = (ord ($Data [2]) << 8) | ord ($Data [3]);
      $hwLength    =  ord ($Data [4]);
      $prLength    =  ord ($Data [5]);
      $arpOpcode   = (ord ($Data [6]) << 8) | ord ($Data [7]);
      $Position = 8;
      
      if ($Length != 8 + ($hwLength * 2) + ($prLength * 2)) {
        trigger_error ('ARP-Packet too short after static');
        
        return false;
      }
      
      // Parse dynamic addresses
      $this->sourceHardwareAddress = substr ($Data, $Position, $hwLength); $Position += $hwLength;
      $this->sourceProtocolAddress = substr ($Data, $Position, $prLength); $Position += $prLength;
      $this->targetHardwareAddress = substr ($Data, $Position, $hwLength); $Position += $hwLength;
      $this->targetProtocolAddress = substr ($Data, $Position, $prLength); $Position += $prLength;
      
      $this->arpHardware = $arpHardware;
      $this->arpProtocol = $arpProtocol;
      $this->arpOpcode   = $arpOpcode;
      
      return true;
    }
    // }}}
    
    // {{{ process
    /**
     * Process this arp-frame and generate a response if neccessary
     * 
     * @access public
     * @return void
     **/
    public function process () {
      // Make sure we have our tools available
      if (!class_exists ('Ethernet_Frame'))
        return;
      
      // Only process IPv4
      if ($this->arpProtocol != 0x0800)
        return;
      
      // Parse protocol-addresses
      $sourceAddress = Ethernet_Frame::getProtocolAddress ($this->arpProtocol, $this->sourceProtocolAddress);
      $targetAddress = Ethernet_Frame::getProtocolAddress ($this->arpProtocol, $this->targetProtocolAddress);
      
      // Update our ARP-Table
      self::$arpTable [$sourceAddress] = $this->sourceHardwareAddress;
      
      // Stop here if its not a request
      if ($this->arpOpcode != $this::OPCODE_REQUEST)
        return;
      
      // Check if the request affects ourself
      global $virtualIP4, $virtualMAC;
      
      if ($targetAddress != ip2long ($virtualIP4))
        return;
      
      // Create a response for this request
      $Response = clone $this;
      $Response->arpOpcode = $this::OPCODE_REPLY;
      $Response->targetHardwareAddress = $this->sourceHardwareAddress;
      $Response->targetProtocolAddress = $this->sourceProtocolAddress;
      $Response->sourceHardwareAddress = $virtualMAC;
      $Response->sourceProtocolAddress = $this->targetProtocolAddress;
      
      return $Response;
    }
    // }}}
    
    // {{{ dump
    /**
     * Generate a binary dump of this arp-frame
     * 
     * @access public
     * @return string
     **/
    public function dump () {
      return
        chr (($this->arpHardware >> 8) & 0xFF) . chr ($this->arpHardware & 0xFF) .
        chr (($this->arpProtocol >> 8) & 0xFF) . chr ($this->arpProtocol & 0xFF) .
        chr (strlen ($this->sourceHardwareAddress)) . chr (strlen ($this->sourceProtocolAddress)) .
        chr (($this->arpOpcode >> 8) & 0xFF) . chr ($this->arpOpcode & 0xFF) .
        $this->sourceHardwareAddress . $this->sourceProtocolAddress .
        $this->targetHardwareAddress . $this->targetProtocolAddress;
    }
    // }}}
    
    // {{{ outputDebug
    /**
     * Output debug-information for this arp-frame
     * 
     * @access public
     * @return void
     **/
    public function outputDebug () {
      // Output ARP-Header
      printf (
        '  ARP Hw %s (0x%04X) Proto %s (0x%04X) Op 0x%02X: ',
        ($this->arpHardware == self::HARDWARE_ETHERNET ? 'Ethernet' : 'Unknown'), $this->arpHardware,
        (class_exists ('Ethernet_Frame') && ($Name = Ethernet_Frame::getProtocolName ($this->arpProtocol)) ? $Name : 'Unknown'), $this->arpProtocol,
        $this->arpOpcode
      );
      
      // Check if we may output further information
      if ($this->arpHardware != self::HARDWARE_ETHERNET) {
        echo 'Unsupported Hardware', "\n";
        
        return;
      } elseif (strlen ($this->targetHardwareAddress) != 6) {
        echo 'Invalid Hardware-Address-Length', "\n";
        
        return;
      } elseif (!class_exists ('Ethernet_Frame')) {
        echo "\n";
        
        return;
      }
      
      // Output Opcode-Specific
      if ($this->arpOpcode == $this::OPCODE_REQUEST)
        $Opcode = 'Who has %s (%s), tell %s (%s)';
      elseif ($this->arpOpcode == $this::OPCODE_REPLY)
        $Opcode = 'Tell %s (%s) that %s is at %s';
      else
        $Opcode = 'Invalid opcode';
      
      printf (
        $Opcode,
        Ethernet_Frame::getProtocolAddress ($this->arpProtocol, $this->targetProtocolAddress, true),
        Ethernet_Frame::getReadableMAC ($this->targetHardwareAddress),
        Ethernet_Frame::getProtocolAddress ($this->arpProtocol, $this->sourceProtocolAddress, true),
        Ethernet_Frame::getReadableMAC ($this->sourceHardwareAddress)
      );
      
      echo "\n";
    }
    // }}}
  }
  
  if (class_exists ('Ethernet_Frame'))
    Ethernet_Frame::registerProtocol (ARP_Frame::PROTOCOL_NUMBER, 'ARP', 'ARP_Frame');

?>