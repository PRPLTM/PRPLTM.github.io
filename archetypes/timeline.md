---
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
draft: true
---

{{< timeline >}}
  {{< container class="container [left||right]" step="[step]" title="[title]">}}
    This is test content 
  {{< /container >}}
{{< /timeline >}}
