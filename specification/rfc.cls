\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{rfc}[RFC]

\LoadClass{article}

\newcommand{\headlinecolor}{\normalcolor}
\RequirePackage{xcolor}
\RequirePackage{fancyhdr}
\RequirePackage{parskip}
\RequirePackage[title, titletoc]{appendix}

\DeclareOption*{\PassOptionsToClass{\CurrentOption}{article}}
\DeclareOption{i-d}{
    \gdef\@pubtype{INTERNET-DRAFT}
    \gdef\@pubhdr{Internet-Draft}
}
\DeclareOption{rfc}{
    \gdef\@pubtype{RFC}
    \gdef\@pubhdr{Request for Comments:}
}
\ProcessOptions\relax

\RequirePackage{fontspec}
\defaultfontfeatures[\rmfamily,\sffamily]{}
\setmainfont[Ligatures=TeX,Scale=0.95]{Cousine}

\gdef\@rfcnum{}
\newcommand{\rfcnum}[1]{\gdef\@rfcnum{#1}}
\newcommand{\pubgroup}[1]{\gdef\@pubgroup{#1}}
\newcommand{\pubdate}[1]{\gdef\@pubdate{#1}}
\newcommand{\address}[1]{\gdef\@address{#1}}
\newcommand{\footertitle}[1]{\gdef\@footertitle{#1}}

\pagestyle{fancy}
\fancyhf{}
\setlength{\headheight}{12pt}
\renewcommand{\headrulewidth}{0.25pt}
\renewcommand{\footrulewidth}{0.25pt}
\fancyhead[l]{\@pubtype\ \@rfcnum}
\fancyhead[c]{\@footertitle}
\fancyhead[r]{\@pubdate}
\fancyfoot[l]{\@author}
\fancyfoot[r]{[Page \thepage]}

\fancypagestyle{firststyle}
{
   \fancyhf{}
   \setlength{\headheight}{35pt}
   \renewcommand{\headrulewidth}{0pt}
   \fancyhead[l]{\@pubgroup \\ \@pubhdr \\ Intended status: Informational}
   \fancyhead[r]{\@author \\ \@address \\ \@pubdate}
   \fancyfoot[l]{\@author}
   \fancyfoot[r]{[Page \thepage]}
}

\RequirePackage[hidelinks, colorlinks=true, allcolors=blue,linktoc=page]{hyperref}

\renewcommand{\numberline}[1]{%
    \ifx\Hy@tocdestname\ltx@empty
        \hb@xt@\@tempdima{#1\hfil}%
    \else 
        \hb@xt@\@tempdima{\hyper@linkstart{link}{\Hy@tocdestname}#1\hyper@linkend\hfil}%
    \fi
}

\renewcommand*\l@section{\@dottedtocline{1}{1.5em}{1.5em}}
\renewcommand*\l@subsection{\@dottedtocline{1}{3.0em}{3.0em}}
\renewcommand\tableofcontents{%
    \null
    Table of Contents\null\par
    \@mkboth{\MakeUppercase\contentsname}{\MakeUppercase\contentsname}%
    \@starttoc{toc}%
}

\renewcommand{\maketitle}{
    \par
    \begingroup
    \newpage \global\@topnum\z@
    \@maketitle
    \setcounter{footnote}{0}
    \let\maketitle\relax
    \let\@maketitle\relax
}

\renewcommand{\@maketitle}{%
    \null
    \thispagestyle{firststyle}
    \begin{center}
        \normalsize\bf\@title
    \end{center}
}

\renewcommand{\section}{%
    \@startsection
    {section}{1}{0pt}{-1.5ex plus -1ex minus -.2ex}%
    {1ex plus .2ex}{\normalsize\bf\headlinecolor}%
}

\renewcommand{\subsection}{%
    \@startsection
    {subsection}{1}{0pt}{-1.5ex plus -1ex minus -.2ex}%
    {1ex plus .2ex}{\normalsize\bf\headlinecolor}%
}

\renewcommand\labelitemi{}
\renewcommand\labelitemii{}
\renewcommand\labelitemiii{}
\renewcommand\labelitemiv{}

\newcommand{\pow}{\^{}}

\RequirePackage[style=alphabetic,backend=biber]{biblatex}
\renewbibmacro{in:}{%
  \ifentrytype{article}
    {}
    {\bibstring{in}%
     \printunit{\intitlepunct}}}
