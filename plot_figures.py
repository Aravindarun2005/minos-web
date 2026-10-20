"""
Draws Figures 2-5 of the Minos paper (Section VII) from the benchmark results.

    python plot_figures.py                       (reads benchmark-results/)
    python plot_figures.py my-results-folder

Creates, in the same folder:
    fig2.png / fig2.pdf   Encryption performance       (a)-(d) side by side
    fig3.png / fig3.pdf   Trapdoor generation performance
    fig4.png / fig4.pdf   Search performance
    fig5.png / fig5.pdf   Detect and trace performance
    and every sub-figure on its own: fig2a.png ... fig4d.png

Needs matplotlib:  python -m pip install matplotlib
"""
import csv
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

FOLDER = sys.argv[1] if len(sys.argv) > 1 else "benchmark-results"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 9,
    "axes.titlesize": 10,
    "axes.labelsize": 9,
    "legend.fontsize": 8,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
})

MINOS_STYLE = dict(linestyle="--", marker="o", markersize=3.5, linewidth=1.2, color="#1f77b4", label="Minos")

FIGURES = {
    "fig2": ("Encryption performance", [
        ("fig2a", "Encryption performance with 1 keyword", "Number of attributes"),
        ("fig2b", "Encryption performance with 10 keywords", "Number of attributes"),
        ("fig2c", "Encryption performance with 1 attribute", "Number of keywords"),
        ("fig2d", "Encryption performance with 10 attributes", "Number of keywords"),
    ], "Fig. 2.  Encryption performance with various number of keywords and attributes."),
    "fig3": ("Trapdoor generation performance", [
        ("fig3a", "Trapdoor generation performance with 1 keyword", "Number of attributes"),
        ("fig3b", "Trapdoor generation performance with 10 keywords", "Number of attributes"),
        ("fig3c", "Trapdoor generation performance with 1 attribute", "Number of keywords"),
        ("fig3d", "Trapdoor generation performance with 10 attributes", "Number of keywords"),
    ], "Fig. 3.  Trapdoor generation performance with various number of keywords and attributes."),
    "fig4": ("Search performance", [
        ("fig4a", "Search performance with 1 keyword", "Number of attributes"),
        ("fig4b", "Search performance with 10 keywords", "Number of attributes"),
        ("fig4c", "Search performance with 1 attribute", "Number of keywords"),
        ("fig4d", "Search performance with 10 attributes", "Number of keywords"),
    ], "Fig. 4.  Search performance with various number of keywords and attributes."),
}


def read(name):
    path = os.path.join(FOLDER, name + ".csv")
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    header, data = rows[0], [r for r in rows[1:] if r]
    columns = {}
    for i, h in enumerate(header):
        columns[h] = [float(r[i]) for r in data]
    return header, columns


def draw(ax, sub_id, title, xlabel):
    header, cols = read(sub_id)
    x = cols[header[0]]
    y = cols[header[1]]
    ax.plot(x, y, **MINOS_STYLE)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Time (ms)")
    ax.set_xlim(left=-3, right=max(x) + 3)
    ax.set_ylim(bottom=0)
    ax.legend(loc="upper left", frameon=True)


def single(sub_id, title, xlabel):
    fig, ax = plt.subplots(figsize=(4.2, 3.2))
    draw(ax, sub_id, title, xlabel)
    fig.tight_layout()
    fig.savefig(os.path.join(FOLDER, sub_id + ".png"), dpi=300)
    plt.close(fig)


def four_panel(fig_id, subs, caption):
    fig, axes = plt.subplots(1, 4, figsize=(17, 3.9))
    letters = "abcd"
    for ax, (sub_id, title, xlabel), letter in zip(axes, subs, letters):
        draw(ax, sub_id, title, xlabel)
        ax.text(0.5, -0.30, "(%s) %s." % (letter, title[0].upper() + title[1:]), transform=ax.transAxes,
                ha="center", va="top", fontsize=10, family="serif")
    fig.text(0.01, 0.005, caption, ha="left", va="bottom", fontsize=10, family="serif")
    fig.subplots_adjust(left=0.045, right=0.99, top=0.9, bottom=0.3, wspace=0.28)
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(FOLDER, fig_id + "." + ext), dpi=300)
    plt.close(fig)
    for sub in subs:
        single(*sub)


def fig5():
    header, cols = read("fig5")
    x = cols[header[0]]
    fig, ax = plt.subplots(figsize=(5.2, 3.6))
    detect = next(h for h in header if h.startswith("Detect (Alg. 9)"))
    trace = next(h for h in header if h.startswith("Trace"))
    ax.plot(x, cols[detect], linestyle="--", marker="s", markersize=3.5, linewidth=1.2, color="#9467bd", label="Detect")
    ax.plot(x, cols[trace], linestyle="--", marker="D", markersize=3.5, linewidth=1.2, color="#8c564b", label="Trace")
    ax.set_title("Detect and trace performance")
    ax.set_xlabel("Number of tests")
    ax.set_ylabel("Time (ms)")
    ax.set_ylim(bottom=0)
    ax.legend(loc="upper left")
    fig.text(0.02, 0.01, "Fig. 5.  Detect and trace performance.", ha="left", va="bottom", fontsize=10, family="serif")
    fig.subplots_adjust(left=0.15, right=0.97, top=0.9, bottom=0.25)
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(FOLDER, "fig5." + ext), dpi=300)
    plt.close(fig)


if __name__ == "__main__":
    if not os.path.isdir(FOLDER):
        sys.exit("Folder '%s' not found. Run run-benchmark.bat first." % FOLDER)
    for fig_id, (_, subs, caption) in FIGURES.items():
        four_panel(fig_id, subs, caption)
        print("created", os.path.join(FOLDER, fig_id + ".png"))
    fig5()
    print("created", os.path.join(FOLDER, "fig5.png"))
    print("Done. PNG files are 300 dpi; PDF files are vector graphics for LaTeX/Word.")
