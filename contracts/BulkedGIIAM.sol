pragma solidity ^0.4.15;
contract BulkedGIIAM {
  /*** 変数の宣言 ***/
  uint32 public diff; // difficulty
  uint256 public target; // target
  uint8 divLimit; // 分割数の限界(16で決定)
  uint16 nowTLDc; // 現状のTLDcの値(16bit)
  uint16 minTLDc; // 最小のTLDcの値(16bit)
  uint16 maxTLDc; // 最大のTLDcの値(16bit)
  
  /*** デバック用 ***/
  bytes15 public strIDSpace; // 7 + 4 + 4 = 15 Bytes
  int256 public proc;
  bytes32 public hashDebug; // 32 Bytesのデータ

  /*** 構造体の定義 ***/
  struct Record64 { // 64bitのicを持つID空間の発行
    OwnerData owner;
    DomainData domain;

    uint8 childNum; mapping(uint8 => uint64) childrenKey64; // レンジ幅がキーとなる
    uint64 pastOwnerNum; mapping(uint64 => OwnerData) pastOwner;
    uint64 pastDomainNum; mapping(uint64 => DomainData) pastDomain;
  }
  struct OwnerData { // 過去の所有者情報
    address addr;
    uint64 blockHeight;
  }
  struct DomainData { // 過去のドメイン情報
    string name;
    uint64 blockHeight;
  }
  
  /*** 変数のマッピング, TLDc: 16bit, SLDc: 40bit, ic: 64bitのucode ***/
  mapping(uint56 => mapping(uint64 => Record64)) record64;   // 所有者、ディレクトリサービスなどを定義
  mapping(uint56 =>  bool) public issued64; // 発行済か
  mapping(uint56 => mapping(uint64 => bool)) valid64; // 譲渡が有効なID空間か(ブランチのHeadであるか)

  /*** コンストラクタの作成 ***/
  function BulkedGIIAM(){
    // ローカル変数
    uint256 coefficient;
    uint256 exponent;
    
    // ディフィカルティの設定
    diff = 0x20ffffff;
    coefficient = uint256(uint24(diff));
    exponent = uint256((diff >> 24));
    target = coefficient << (8 * (exponent - 3)); // 0x03a30c0000000000000000000000000000000000000000000000000000000000, バグなし
    hashDebug = bytes32(target);
    // 分割数の限界
    divLimit = 16;
    // TLDcの初期設定
    nowTLDc = 0x1001;
    minTLDc = 0x1001;
    maxTLDc = 0x1fff;

    // デバック変数の初期化
    strIDSpace = bytes15(0);
    proc = 0;
  }

  // increment
  function incrementTLDc() public returns(bool){
    // 8191 = 0x1fff in hex
    if (nowTLDc < maxTLDc) {
      nowTLDc = nowTLDc + 1;
      return true;
    } else {
      return false;
    }      
  }
  // updateDiffTarget
  function updateDiffTarget(uint32 _diff) public returns(bool){
    // ローカル変数
    uint256 coefficient;
    uint256 exponent;
    // 入力の条件が満たされているか
    if (false) {
      return false;
    }    
    // アップデート
    diff = _diff;
    coefficient = uint256(uint24(diff));
    exponent = uint256((diff >> 24));
    target = coefficient << (8 * (exponent - 3)); // 0x03a30c0000000000000000000000000000000000000000000000000000000000
    hashDebug = bytes32(target);
    return true;
  }

  
  /*** メソッド一覧 ***/
  function regIDSpace64(uint56 _inputKey, uint64 _blockHeight, uint64 _nonce) public returns(bool){
    /** 変数の宣言 **/
    // 32bitのレンジを示す(最大2^32=65536*65536の分割ができる)
    uint64 geneRange = 0x00000000ffffffff;
    uint256 blockHash = uint256(block.blockhash(_blockHeight));
    uint16 TLDc = uint16(_inputKey >> 40);
    uint256 hash;
    
    /** 入力に対する処理(エラー処理含む) **/
    // TLDcが有効なTLDcか
    if (TLDc > nowTLDc || TLDc < minTLDc) {
      proc = -1;
      return false;
    }
    // 発行済のID空間か
    if (issued64[_inputKey]) {
      proc = -2;
      return false;
    }
    // ブロック高が有効なブロックか, Ethereumの仕様を利用
    if (blockHash == 0) {
      proc = -3;
      return false;
    }
    // PoWを実行してtargetより小さいか確認
    hash = uint256(sha3(_inputKey, blockHash, _nonce));
    if (hash > target) {
      proc = -4;
      return false;
    }

    /** ID空間の発行処理を実行 **/
    // 所有権を付与する、ディジタル署名による確認は不要(送信者のアドレスが入るため)
    record64[_inputKey][geneRange].owner.addr = msg.sender;
    record64[_inputKey][geneRange].owner.blockHeight = uint64(block.number);
    // ID空間が発行済になったことを示す
    issued64[_inputKey] = true;
    // ID空間が譲渡可能であることを示す
    valid64[_inputKey][geneRange] = true;
    proc = 1;
    return true;
  }

  // 権利の譲渡を行うトランザクション
  function assignRight64(uint120 _keyIDSpaceAndRange, uint64 _validateBlockHeight, address _to, uint8 _v, bytes32 _r, bytes32 _s) public returns(bool){
    /** 変数の宣言 **/
    uint56 keyIDSpace = uint56(_keyIDSpaceAndRange >> 64);
    uint64 keyRange = uint64(_keyIDSpaceAndRange);
    uint64 index;

    /** 入力に対する処理(エラー含む) **/
    // 発行済のID空間でない場合
    if (!issued64[keyIDSpace]) {
      proc = -12;
      return false;
    }
    // ID空間が譲渡可能なものであるか確認
    if (!valid64[keyIDSpace][keyRange]) {
      proc = -13;
      return false;
    }
    // 送信者が所有しているID空間であるか確認
    if (record64[keyIDSpace][keyRange].owner.addr != msg.sender) {
      proc = -14;
      return false;
    }
    // 現在のブロック高がTxが有効であるブロック高を超えたら無効になる
    if (block.number > _validateBlockHeight) {
      proc = -15;
      return false;
    }    
    // ディジタル署名の検証
    hashDebug = sha3(_keyIDSpaceAndRange, _validateBlockHeight);
    if (ecrecover(bytes32(sha3(_keyIDSpaceAndRange, _validateBlockHeight)), _v, _r, _s) != _to) {
      proc = -16;
      return false;
    }
    
    // ID空間の権利情報を更新
    index = record64[keyIDSpace][keyRange].pastOwnerNum;
    record64[keyIDSpace][keyRange].pastOwner[index] = record64[keyIDSpace][keyRange].owner;
    record64[keyIDSpace][keyRange].pastOwnerNum = index + 1;
      
    // 署名を行った人に権利を譲渡
    record64[keyIDSpace][keyRange].owner.addr = _to;
    record64[keyIDSpace][keyRange].owner.blockHeight = uint64(block.number);
    
    proc = 2;
    return true;
  }

  // ドメイン情報の更新
  function updateDomain64(uint120 _keyIDSpaceAndRange, string _domain) public returns(bool){
    /** 変数の宣言 **/
    uint56 keyIDSpace = uint56(_keyIDSpaceAndRange >> 64);
    uint64 keyRange = uint64(_keyIDSpaceAndRange);
    uint64 index;

    /** エラー処理 **/
    // 送信者が所有しているID空間か
    if (record64[keyIDSpace][keyRange].owner.addr != msg.sender) {
      proc = -21;
      return false;
    }
    // 長すぎる入力
    if (bytes(_domain).length > 253) {
      proc = -22;
      return false;
    }

    // 現在のドメインを過去のドメインとして登録
    // ドメインが登録されている場合のみ、この処理を行う
    if (record64[keyIDSpace][keyRange].domain.blockHeight != 0) {
      index = record64[keyIDSpace][keyRange].pastDomainNum;
      record64[keyIDSpace][keyRange].pastDomain[index] = record64[keyIDSpace][keyRange].domain;
      record64[keyIDSpace][keyRange].pastDomainNum = index + 1;
    }
    // ドメイン名の更新
    record64[keyIDSpace][keyRange].domain.name = _domain;
    record64[keyIDSpace][keyRange].domain.blockHeight = uint64(block.number);

    proc = 3;
    return true;
  }

  struct TargetInfo64 {
    uint56 keyIDSpace;
    uint64 keyRange;
    uint32 startOfRange;
    uint32 endOfRange;
  }
  struct CheckSort64 {
    uint32 middle;
    uint8 toPlace;
  }
  struct Tmp64 {
    uint64 newKeyRange;
    uint8 i;
    uint8 j;
  }
  
  // 譲渡トランザクション
  function transferIDSpace64(uint120 _keyIDSpaceAndRange, uint64 _validateBlockHeight, uint32[] _middleOfRange, uint8[] _toPlace, address[] _to,
			     uint8[] _v, bytes32[] _r, bytes32[] _s) public returns(int){
    /** 変数の宣言 **/
    TargetInfo64 memory tgt;
    tgt.keyIDSpace = uint56(_keyIDSpaceAndRange >> 64);
    tgt.keyRange = uint64(_keyIDSpaceAndRange);
    tgt.startOfRange = uint32(tgt.keyRange >> 32);
    tgt.endOfRange = uint32(tgt.keyRange);
    CheckSort64 memory chk;
    Tmp64 memory tmp;

    /*
    if (true) {
      proc = -300;
      return proc;
    }
    */
    // ID空間所有者が作成したTxか
    if (record64[tgt.keyIDSpace][tgt.keyRange].owner.addr != msg.sender) {
      proc = -301;
      return proc;
    }
    // 譲渡が可能なID空間か
    if (!valid64[tgt.keyIDSpace][tgt.keyRange]) {
      proc = -302;
      return proc;
    }
    // 現在のブロック高がTxが有効であるブロック高を超えたら無効になる
    if (block.number > _validateBlockHeight) {
      proc = -303;
      return proc;
    }
    // 入力数が分割数限界以下の範囲に収まっているか
    if ((_middleOfRange.length + 1) > divLimit) {
      proc = -304;
      return proc;
    }
    // 分割の開始と終了がkeyOfRangeの範囲に収まっているか
    // middleOfRange = [a_1, a_2, ..., a_k](1 <= k <= 15)として、[startOfRange, a_1], [a_1 + 1, a_2], ..., [a_k + 1, endOfRange]となる
    if ((_middleOfRange[0] < tgt.startOfRange) || ((tgt.endOfRange - 1) < _middleOfRange[_middleOfRange.length - 1])) {
      proc = -305;
      return proc;
    }
    // 分割がソートされているか確認(全て異なる値の上で)
    chk.middle = _middleOfRange[0];
    for (tmp.i = 1; tmp.i < _middleOfRange.length; tmp.i++) {
      if (!(chk.middle < _middleOfRange[tmp.i])) {
        proc = -306;
        return proc;
      }
      chk.middle = _middleOfRange[tmp.i];
    }
    // 譲渡先が所有するID空間数が分割数をオーバーしていないか確認する
    if (_toPlace.length > (_middleOfRange.length + 1)) {
      proc = -307;
      return proc;
    }
    // 所有者が指定した空間と新しい所有者の人数が一致する必要
    if ((_toPlace.length != _to.length) || (_to.length != _v.length) || (_v.length != _r.length) || (_r.length != _s.length)) {
      proc = -308;
      return proc;
    }
    // 所有者が所有する分割対象がdivSizeの範囲に収まっているか(この条件を満たすために入力を階段状にする必要がある)
    chk.toPlace = _toPlace[0];
    for (tmp.i = 1; tmp.i < _toPlace.length; tmp.i++) {
      if (!(chk.toPlace < _toPlace[tmp.i])) {
        proc = -309;
        return proc;
      } else if (!(_toPlace[tmp.i] < (_middleOfRange.length + 1))) {
	proc = -310;
	return proc;
      }
      chk.toPlace = _toPlace[tmp.i];
    }
    // 受け手側により生成されたディジタル署名の検証 
    for (tmp.i = 0; tmp.i < _to.length; tmp.i++) {
      if (ecrecover(bytes32(sha3(_keyIDSpaceAndRange, _validateBlockHeight, _middleOfRange, _toPlace, _to)), _v[tmp.i], _r[tmp.i], _s[tmp.i]) != _to[tmp.i]) {
        proc = -311;
        return proc;
      }
    }
    /** 入力ID空間の無効化 **/
    // 譲渡ができないID空間(履歴)に
    valid64[tgt.keyIDSpace][tgt.keyRange] = false;

    /** 新しいID空間の出力と親ノードに子ノード情報を記憶させる **/
    // 子供の数を代入
    record64[tgt.keyIDSpace][tgt.keyRange].childNum = uint8(_middleOfRange.length + 1);
    
    // 新しいID空間のKeyの記述
    tmp.i = 0; tmp.j = 0;
    for (; tmp.i < _middleOfRange.length + 1; tmp.i++) {
      if (tmp.i == _toPlace[tmp.j]) { // 譲渡先のデータベースを更新
	// tmp.i == 0, tmp.i == _middleOfRange.length, the othersで場合分け
	if (tmp.i == 0) {
	  tmp.newKeyRange = (uint64(tgt.startOfRange) << 32) + uint64(_middleOfRange[tmp.i]);
	} else if (tmp.i == _middleOfRange.length) {
	  tmp.newKeyRange = (uint64((_middleOfRange[tmp.i - 1] + 1)) << 32) + uint64(tgt.endOfRange);
	} else {
	  tmp.newKeyRange = (uint64((_middleOfRange[tmp.i - 1] + 1)) << 32) + uint64(_middleOfRange[tmp.i]);
	}
	// 子ノードのデータベースを更新
	record64[tgt.keyIDSpace][tmp.newKeyRange].owner.addr = _to[tmp.j];
	record64[tgt.keyIDSpace][tmp.newKeyRange].owner.blockHeight = uint64(block.number);
	// 親ノードの子ノード情報データベースを更新
	record64[tgt.keyIDSpace][tgt.keyRange].childrenKey64[tmp.i] = tmp.newKeyRange;
	// jのオーバーフロー対策
	if (tmp.j != _toPlace.length - 1) {
	  tmp.j++;
	}
      } else { // 所有者のデータベースを更新
	if (tmp.i == 0) {
	  tmp.newKeyRange = (uint64(tgt.startOfRange) << 32) + uint64(_middleOfRange[tmp.i]);
	} else if (tmp.i == _middleOfRange.length) {
	  tmp.newKeyRange = (uint64((_middleOfRange[tmp.i - 1] + 1)) << 32) + uint64(tgt.endOfRange);
	} else {
	  tmp.newKeyRange = (uint64((_middleOfRange[tmp.i - 1] + 1)) << 32) + uint64(_middleOfRange[tmp.i]);
	}
	// 子ノードのデータベースを更新
	record64[tgt.keyIDSpace][tmp.newKeyRange].owner.addr = msg.sender;
	record64[tgt.keyIDSpace][tmp.newKeyRange].owner.blockHeight = uint64(block.number);
	// 親ノードの子ノード情報データベースを更新
	record64[tgt.keyIDSpace][tgt.keyRange].childrenKey64[tmp.i] = tmp.newKeyRange;
      }
    }
    proc = 4;
    return proc;
  }
  
  // 所有権、及びドメイン情報の確認
  function getAddr64(uint120 _keyIDSpaceAndRange) public returns(address){
    uint56 keyIDSpace = uint56(_keyIDSpaceAndRange >> 64);
    uint64 keyRange = uint64(_keyIDSpaceAndRange);
    return record64[keyIDSpace][keyRange].owner.addr;
  }
  function getPastAddr64(uint120 _keyIDSpaceAndRange, uint64 _index) public returns(address){
    uint56 keyIDSpace = uint56(_keyIDSpaceAndRange >> 64);
    uint64 keyRange = uint64(_keyIDSpaceAndRange);
    return record64[keyIDSpace][keyRange].pastOwner[_index].addr;
  }
  function getDomain64(uint120 _keyIDSpaceAndRange) public returns(string){
    uint56 keyIDSpace = uint56(_keyIDSpaceAndRange >> 64);
    uint64 keyRange = uint64(_keyIDSpaceAndRange);
    return record64[keyIDSpace][keyRange].domain.name;
  }
  function getPastDomain64(uint120 _keyIDSpaceAndRange, uint64 _index) public returns(string){
    uint56 keyIDSpace = uint56(_keyIDSpaceAndRange >> 64);
    uint64 keyRange = uint64(_keyIDSpaceAndRange);
    return record64[keyIDSpace][keyRange].pastDomain[_index].name;
  }
  // 譲渡が可能な空間か
  function getValid64(uint120 _keyIDSpaceAndRange) public returns(bool){
    uint56 keyIDSpace = uint56(_keyIDSpaceAndRange >> 64);
    uint64 keyRange = uint64(_keyIDSpaceAndRange);
    return valid64[keyIDSpace][keyRange];
  }
  // 発行済のID空間か
  function getIssued64(uint56 _keyIDSpace) public returns(bool){
    return issued64[_keyIDSpace];
  }
  
  
}
