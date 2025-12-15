document.addEventListener("DOMContentLoaded", () => {

  if (!window.HEADERSCOPE_DATA) {
    console.error("HeaderScope: No hay data para gráficos");
    return;
  }

  const data = window.HEADERSCOPE_DATA;

  /* =========================
     GRÁFICO 1: CABECERAS
     ========================= */
  const headersCtx = document.getElementById("headersChart");
  if (headersCtx) {
    new Chart(headersCtx, {
      type: "bar",
      data: {
        labels: ["Clásicas", "Modernas", "Cookies"],
        datasets: [{
          label: "Cantidad",
          data: [
            data.headers.classic,
            data.headers.modern,
            data.headers.cookies
          ],
          backgroundColor: [
            "#3b82f6", // blue
            "#22c55e", // green
            "#f59e0b"  // amber
          ],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false }
        },
        scales: {
          y: {
            beginAtZero: true,
            ticks: { precision: 0 }
          }
        }
      }
    });
  }

  /* =========================
     GRÁFICO 2: SEVERIDAD
     ========================= */
  const severityCtx = document.getElementById("severityChart");
  if (severityCtx) {
    new Chart(severityCtx, {
      type: "doughnut",
      data: {
        labels: ["High", "Medium", "Low", "Info"],
        datasets: [{
          data: [
            data.severity.High || 0,
            data.severity.Medium || 0,
            data.severity.Low || 0,
            data.severity.Info || 0
          ],
          backgroundColor: [
            "#ef4444", // red
            "#f97316", // orange
            "#22c55e", // green
            "#3b82f6"  // blue
          ]
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: "bottom"
          }
        },
        cutout: "65%"
      }
    });
  }

  /* =========================
     GRÁFICO 3: SCORE
     ========================= */
  const scoreCtx = document.getElementById("scoreChart");
  if (scoreCtx) {
    const score = data.score;
    const risk = 100 - score;

    new Chart(scoreCtx, {
      type: "doughnut",
      data: {
        labels: ["Score", "Riesgo"],
        datasets: [{
          data: [score, risk],
          backgroundColor: [
            score >= 70 ? "#22c55e" : score >= 40 ? "#f59e0b" : "#ef4444",
            "#1f2937"
          ]
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: "bottom"
          },
          tooltip: {
            callbacks: {
              label: (ctx) => `${ctx.label}: ${ctx.raw}`
            }
          }
        },
        cutout: "70%"
      }
    });
  }

});
