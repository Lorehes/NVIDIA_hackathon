import Link from "next/link";

const READ = [
  { name: "안전해요", bg: "var(--green)", color: "#fff", m: <>문자가 말한 회사의 <b>진짜 사이트</b>예요.</>, s: "그래도 카드 번호·비밀번호를 물으면 한 번 더 생각하세요." },
  { name: "조심하세요", bg: "var(--amber)", color: "var(--ink)", m: <>가짜라고 딱 잘라 말할 수는 없지만 <b>위험한 점</b>이 있어요.</>, s: "회사 대표번호로 직접 물어보세요." },
  { name: "가짜로 의심돼요", bg: "var(--red)", color: "#fff", m: <>진짜 회사를 <b>흉내 낸 가짜</b>일 가능성이 높아요.</>, s: "링크를 누르지 말고, 문자를 지우세요." },
  { name: "알 수 없어요", bg: "var(--g700)", color: "#fff", m: <>확인할 자료가 없거나 조사가 멈췄어요. <b>안전하다는 뜻이 아니에요.</b></>, s: "잠시 뒤 다시 확인해 보세요." },
];

const FAQ: { q: string; a: string }[] = [
  { q: "링크를 붙여 넣기만 해도 위험하지 않나요?", a: "괜찮아요. 붙여 넣은 링크는 내 휴대폰에서 열리지 않아요. 바깥과 떨어진 안전 공간에서만 열어봐요." },
  { q: "\"안전해요\"가 나오면 무조건 믿어도 되나요?", a: "아니에요. \"안전해요\"는 링크의 주인이 문자가 말한 회사와 같고 위험한 점을 찾지 못했다는 뜻이에요. 문자를 보낸 전화번호가 진짜인지는 알 수 없고, 카드 번호나 비밀번호를 적으라고 하면 한 번 더 멈추고 생각해야 해요." },
  { q: "왜 1분이나 걸리나요?", a: "링크를 바로 여는 대신, 한 곳만 문을 여는 안전 공간에서 열어보고 페이지 속 내용까지 살펴보기 때문이에요. 안전을 위해 한 번에 한 건씩 확인해서 앞에 기다리는 사람이 있으면 조금 더 걸려요." },
  { q: "AI가 틀리면 어떡하나요?", a: "진짜·가짜를 정하는 일은 AI가 아니라 미리 정해 둔 규칙이 해요. AI는 조사를 돕고 쉬운 말로 설명만 써요. 그래서 AI가 실수로 \"안전해요\"라고 말할 수 없어요. 조사가 멈추면 \"알 수 없어요\"로 알려드려요." },
  { q: "어떤 회사까지 확인할 수 있나요?", a: "각 회사 공식 홈페이지에서 직접 확인한 주소를 모아 둔 목록에 있는 회사만 진짜 주소와 비교해요. 목록에 없는 회사는 \"가짜\"라고 단정하지 않고, 위험한 점이 있는지만 알려드려요." },
];

export function How() {
  return (
    <div className="how">
      <div className="col" style={{ gap: 12 }}>
        <h1>이렇게 이용하세요</h1>
        <p className="lead">이상한 문자를 받았을 때, 링크를 누르지 않고도 진짜인지 가짜인지 알 수 있어요.</p>
      </div>

      <div className="how-steps">
        <div className="how-step">
          <div className="how-ph">휴대폰 화면: 문자를 길게 눌러 &quot;복사&quot;</div>
          <div className="in">
            <span className="num">1</span>
            <h3>문자를 복사해요</h3>
            <p>
              받은 문자를 손가락으로 <b>길게 누르면</b> &quot;복사&quot;가 나와요. 링크는 누르지 마세요.
            </p>
          </div>
        </div>
        <div className="how-step">
          <div className="how-ph">이 사이트 입력 칸에 &quot;붙여넣기&quot;</div>
          <div className="in">
            <span className="num">2</span>
            <h3>여기에 붙여 넣어요</h3>
            <p>
              첫 화면의 큰 칸을 길게 눌러 <b>붙여넣기</b>를 눌러요. 문자 전체도, 링크만도 괜찮아요.
            </p>
          </div>
        </div>
        <div className="how-step">
          <div className="how-ph">결과 화면: 색깔 표시 + 이유</div>
          <div className="in">
            <span className="num">3</span>
            <h3>1분쯤 기다려요</h3>
            <p>
              <b>확인하기</b>를 누르면 저희가 대신 열어보고, 결과와 이유를 알려드려요.
            </p>
          </div>
        </div>
      </div>

      <div className="col" style={{ gap: 18 }}>
        <h2>결과는 이렇게 읽어요</h2>
        <div className="read4">
          {READ.map((r) => (
            <div className="read" key={r.name}>
              <span className="pill2" style={{ background: r.bg, color: r.color }}>
                {r.name}
              </span>
              <span className="m">{r.m}</span>
              <span className="s">{r.s}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="two-col">
        <div className="box-white">
          <h2>이 서비스가 알 수 없는 것</h2>
          <span style={{ fontSize: 16, lineHeight: 1.6, color: "var(--g700)" }}>
            모르는 것은 결과 화면의 <b style={{ color: "var(--ink)" }}>&quot;확인하지 못한 것&quot;</b>에 따로 적어 드려요.
          </span>
          <div className="x-list">
            <div>
              <span className="x">✕</span>
              <span>
                문자를 보낸 <b>전화번호</b>가 진짜 회사 번호인지
              </span>
            </div>
            <div>
              <span className="x">✕</span>
              <span>
                <b>링크가 없는</b> 문자 (전화하라는 문자 등)
              </span>
            </div>
            <div>
              <span className="x">✕</span>
              <span>이메일, 카카오톡으로 온 메시지</span>
            </div>
            <div>
              <span className="x">✕</span>
              <span>페이지가 열린 뒤 스스로 바뀌는 내용</span>
            </div>
          </div>
        </div>
        <div className="box-dark">
          <h2>이미 링크를 눌렀거나 정보를 적었다면</h2>
          <div className="hot">
            <div>
              <span>카드 번호를 적었어요</span>
              <b>카드 회사에 바로 전화</b>
            </div>
            <div>
              <span>계좌·돈을 보냈어요</span>
              <b>은행에 지급정지 요청</b>
            </div>
            <div>
              <span>사기 피해를 신고하고 싶어요</span>
              <b className="n">112</b>
            </div>
            <div>
              <span>모르는 앱이 깔렸어요 · 상담</span>
              <b className="n">118</b>
            </div>
          </div>
        </div>
      </div>

      <div className="col" style={{ gap: 14 }}>
        <h2>자주 묻는 질문</h2>
        <div className="faq">
          {FAQ.map((f, i) => (
            <details key={f.q} open={i === 0}>
              <summary>{f.q}</summary>
              <p className="ans-t">{f.a}</p>
            </details>
          ))}
        </div>
      </div>

      <div className="cta">
        <b>받은 문자, 지금 확인해 볼까요?</b>
        <Link href="/" className="btn-main">
          확인하러 가기
        </Link>
      </div>
    </div>
  );
}
